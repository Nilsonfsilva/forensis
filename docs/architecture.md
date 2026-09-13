# Forensis Architecture — o mapa do byte

> **Language note:** this document is the internal study reference for
> the project structure and is written in Portuguese. All other
> documentation in this repository is in English.

Forensis lê bytes crus de block devices e imagens de disco e, camada por
camada, transforma-os em um *forensic model* independente de filesystem.
Este documento é o **mapa organogramico** do projeto: mostra o que cada
arquivo-chave faz, quais bytes entram e saem de cada camada, e em quais
pontos o fluxo é **vertical** (sobe em abstração ou desce para o disco) e
em quais ele é **horizontal** (irmãos que se alternam sob um mesmo
contrato).

O projeto é um Cargo workspace com camadas verticais rígidas entre as
interfaces e o código que conversa com os bytes.

## Workspace layout

| Crate | Papel |
| --- | --- |
| `forensis-core` | Acesso a bytes, disco, partição e filesystem, o modelo forense e o motor de recuperação. |
| `forensis-app` | Casos de uso compartilhados pelas interfaces: descoberta de fontes, inspeção e coordenação da recuperação. |
| `forensis-cli` | Interface de linha de comando, binário `forensis`. |
| `forensis-tui` | Interface de terminal, binário `forensis-tui`. |

> Toda a lógica (disco, partição, filesystems, modelo forense e recuperação)
> vive hoje em `forensis-core`; uma modularização futura poderia dividi-lo em
> crates por camada.

## Mapa-mãe: como o byte atravessa as camadas

```text
                              (1) VERTICAL DE SUBIDA
                               bytes crus  ->  abstração
                    [H-A] = momento horizontal (irmãos sob um contrato)

   EvidenceSource / caminho        app/source.rs          (sem bytes)
        |
        v
   ImageReader (Readable)          disk/image_reader.rs   <<< o BYTE entra aqui
        |  LBA 0 / LBA 1 (512 B)
        v                                                    [H-A]
   PartitionTableDetector ------>  MBR   |   GPT            (irmãs)
        |
        v  boot sector (512 B) + superblock ext (1024 B)
   FileSystemDetector -------->    NTFS | EXT4 | FAT32 | exFAT   [H-B]
        |                                        ^
        |                          (fan-out horizontal: o detector escolhe
        |                           em qual irmã o parsing segue)
        v
   NtfsFileSystem::parse           ntfs/boot_sector.rs  (geometria)
        |
        v  mft_offset = partition_offset + mft_cluster * spc * bps
   NtfsMftReader                   ntfs/mft_reader.rs
        |  MFT record 0 -> $MFT DATA (non-resident) -> data runs
        v  lcn -> partition_offset + lcn * bytes_per_cluster
   DataRunReader                   ntfs/data_run_reader.rs
        |  reconstrói o stream lógico da MFT
        v
   MftRecord -> MftParser          ntfs/mft_record.rs, mft_parser.rs,
        |                          mft_attribute.rs, file_name.rs,
        v                          standard_information.rs, index_*.rs
   Investigation (NTFS-interno)    ntfs/investigation.rs
        |  to_forensic_model()
        v                             (2) VERTICAL DE SUBIDA (topo)
   ForensicModel + ForensicTree    forensic/model.rs, forensic/tree.rs
        |                          (sem bytes, independente de FS)
        v
   app: inspection/recovery        app/inspection.rs, app/recovery.rs
        |                                                     [H-C]
        +----------------  cli   |   tui  ------------------+
                          interfaces irmãs consumindo o mesmo app
        |
        v                          (3) VERTICAL DE DESCIDA NA RECUPERAÇÃO
   PhysicalRecoveryEngine          recovery/engine.rs
        |  reelê o byte no disco:
        |   Physical -> partition_offset + sector * 512
        |   Sparse   -> zeros reconstruídos
        |   Inline   -> bytes já carregados no modelo
        v
   bytes recuperados -> sha256 -> arquivo forensis-recovery/<ticket>
```

Regra de ouro do mapa: **cada camada conhece apenas o contrato da
vizinha** — embaixo o `Readable` (bytes), em cima o `ForensicModel`
(abstração). Nada fora da camada do filesystem enxerga MFT/inode/DATA.

## Transições vertical × horizontal

| # | Transição | Onde | Por quê |
| --- | --- | --- | --- |
| V1 | **Subida vertical** (bytes → modelo) | `image_reader` → `investigation::to_forensic_model` | Cada camada sobe um degrau de abstração: bytes → partições → tipo de FS → geometria → MFT → registros → modelo. |
| H1 | **Horizontal: MBR \| GPT** | `partition/partition_table.rs` | Duas implementações irmãs escondidas atrás do enum `PartitionTable`; o `PartitionTableDetector` escolhe a fila e o consumidor só vê `Vec<Partition>`. |
| H2 | **Horizontal: NTFS \| EXT4 \| FAT32 \| exFAT** | `filesystem/detector.rs` + `filesystem/<fs>/` | O detector abre um leque: cada filesystem é uma irmã que lê do mesmo `Readable` e **deve produzir o mesmo `ForensicModel`**. NTFS, EXT4 e FAT32 têm `is_supported() == true`. |
| H3 | **Horizontal interno ao NTFS** | `ntfs/mft_parser.rs` | Um registro MFT é um leque de atributos: `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA`, `$INDEX_ROOT`/`$INDEX_ALLOCATION` — cada um parseado por um arquivo irmão. |
| V2 | **Subida vertical (final)** | `forensic/model.rs` + `forensic/tree.rs` | Depois do modelo, app e interfaces só consomem `ForensicEntry`/`ForensicTree`. A aplicação nunca mais vê estruturas NTFS. |
| H4 | **Horizontal: CLI × TUI** | `forensis-cli/`, `forensis-tui/` | Interfaces irmãs que chamam o mesmo `app::{discover_sources, inspect_image, recover_*, next_recovery_ticket}`. |
| V3 | **Descida vertical (recuperação)** | `recovery/engine.rs` | O `PhysicalRecoveryEngine` pega o `ForensicEntry` (topo da abstração) e **desce de volta ao disco** para reler os bytes e remontar o objeto. |

## Catálogo de arquivos-chave por camada

Legenda das colunas de entrada/saída: o que **entra** (bytes ou
estruturas) e o que **sai** (estruturas ou bytes) de cada arquivo.

### Camada de evidência — sem bytes

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `crates/forensis-app/src/source.rs` | caminho de arquivo/diretório/device (`/dev`) | `discover_sources` classifica arquivo → `DiskImage`, block device → `BlockDevice`/`Partition`, diretório → varre e ordena fontes; `resolve_source` exige um único caminho | `Vec<EvidenceSource>` (`EvidenceSourceKind`: BlockDevice/Partition/DiskImage) |

### Camada de bytes crus

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `crates/forensis-core/src/disk/image_reader.rs` | caminho; `ImageReader::open` | detecta block device (Linux: `/sys/class/block/<name>/size` setores×512) ou arquivo (seek fim); implementa **`Readable`** | `read_at(offset: ByteOffset, &mut [u8])` — a única porta de leitura do byte cru |
| `crates/forensis-core/src/disk/types.rs` | — | `ByteOffset`, `ByteSize`, `Sector`, `Cluster` (newtypes fortes) | offsets/tamanhos tipados |
| `crates/forensis-core/src/traits.rs` | — | contrato `Readable` (+ `Storage`, `FileSystem`, `PartitionTableReader`, `Carver`) | o "soquete" que todas as camadas usam para ler |

### Camada de partições (H1) — bytes → partições

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `partition/partition_table.rs` | setor 1 (512 B): `"EFI PART"` → GPT; setor 0 (512 B): `0x55AA` + entrada MBR reconhecida (+8 start_lba, +12 contagem) | `PartitionTableDetector::detect` + `parse`; enum `PartitionTable { Mbr, Gpt }` | `Option<PartitionTable>`; `partitions()`: `Vec<Partition { number, start_sector, sector_count, partition_type }>` |
| `partition/mbr.rs` | LBA 0: 4 entradas em `446 + i*16` | decodifica a tabela clássica de 4 entradas; `parse_partition_type` valida os tipos | `Partition` (LBA = setor, não offset) |
| `partition/gpt.rs` | header + array de entradas (com caps defensivos) | header `"EFI PART"` + caminhada protegida das entradas | `Partition` |

> Conversão setor→byte (`start_sector * 512`) acontece na camada de
> aplicação (`app/inspection.rs` e `app/recovery.rs`), não aqui.

### Camada de detecção de filesystem (H2) — bytes → tipo de FS

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `filesystem/detector.rs` | 512 B no offset da partição (+ 1024 B em `offset+1024` para ext) | `detect_at`: `"NTFS"` em `[3..7]`; `"FAT32"` em qualquer janela dos 512 B; magic ext `0xEF53` em `superblock[56..58]` | `FileSystemType` (Ntfs/Ext4/Fat32/ExFat/Xfs/Btrfs/HfsPlus/Apfs/Unknown) |
| `filesystem/detector.rs` | `FileSystemType` | **gate de suporte** `is_supported()` (hoje só `Ntfs`) — o que contém o fan-out H2 | `bool` |
| `filesystem/detector.rs` | partição/offset | `open_ntfs`/`open_ntfs_at` → `NtfsFileSystem::parse` | `NtfsFileSystem` pronto para investigar |

### Camada NTFS — geometria (V1, 5.º degrau)

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `ntfs/boot_sector.rs` | 512 B no `partition_offset` | valida assinatura `"NTFS"`, lê `bytes_per_sector[11]`, `sectors_per_cluster[13]`, `total_sectors[40]`, `mft_cluster[48]`, `mft_mirror[56]`, tamanhos de registro/índice (`[64]`, `[68]` sinal/exp) | `NtfsBootSector` (geometria) + `partition_offset` |

### Camada NTFS — MFT (V1, 6.º degrau) — bytes → stream lógico

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `ntfs/mft_reader.rs` | geometria do boot | `mft_offset = partition_offset + mft_cluster * sectors_per_cluster * bytes_per_sector`; `read_record(i) = mft_offset + i * mft_record_size` | `MftRecord` (bytes brutos do registro i) |
| `ntfs/data_run_reader.rs` | `DataRun[]` + `Readable` | `lcn_offset(lcn) = partition_offset + lcn * bytes_per_cluster`; run `Some(lcn)` lê do disco, run `None` (sparse) devolve zeros; `read_runs` respeita `real_size` | bytes do $MFT / de qualquer `$DATA` |
| `ntfs/boot_sector.rs` (`investigate`) | $MFT record 0 parseado | orquestra: lê record 0 → acha `$DATA` non-resident → reconstrói o **stream lógico completo da MFT** pelos data runs → para cada slot não-zero cria `MftRecord` e chama `process_mft_record` | `Investigation` |

### Camada NTFS — registro e atributos (H3, 7.º degrau) — bytes → estruturas

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `ntfs/mft_record.rs` | bytes do slot + índice | `new`: aplica **USA fixup** (correção do update sequence array), guarda assinatura/header | `MftRecord` com header validado |
| `ntfs/mft_parser.rs` | `MftRecord` | `parse`: header (flags, usa, tamanhos, base_record) + itera atributos | `ParsedMftRecord` com `file_names[]`, `data (DataAttribute)`, `index_root`, `mft_flags` |
| `ntfs/mft_attribute.rs` | buffer do atributo | `MftAttribute::parse` (type, length, non-resident, name) + `AttributeType::from_raw` | atributo bruto tipado |
| `ntfs/data_run.rs` | bytes do runlist de um `$DATA` non-resident | header: nibble alto = largura LCN, nibble baixo = largura da contagem; LCN é **relativo** ao run anterior; `0x00` termina; `lcn_size == 0` = sparse | `Vec<DataRun { lcn: Option<i64>, cluster_count }>` |
| `ntfs/data_attribute.rs` | atributo `$DATA` parseado | expõe `non_resident`, `real_size`, `resident_data`, `data_runs` | `DataAttribute` |
| `ntfs/file_name.rs`, `standard_information.rs` | subtipos de atributo | `$FILE_NAME` (nome/pai/flags), `$STANDARD_INFORMATION` | metadados de identidade |
| `ntfs/index_root.rs`, `index_allocation.rs`, `index_entry.rs`, `directory.rs` | `$INDEX_ROOT`/`$INDEX_ALLOCATION` | `$INDEX_ROOT` → `NtfsDirectory` com seus `INDEX_ENTRY` preservados | diretórios NTFS |

### Camada NTFS → Modelo (V1, topo) — estruturas → modelo genérico

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `ntfs/investigation.rs` | `ParsedMftRecord` + `NtfsDirectory` | `process_mft_record`: `$FILE_NAME` → `InvestigationEntry`; `INDEX_ROOT` → diretório (sem duplicar entradas); `resolve_path` (proteção contra ciclos) **dentro do NTFS**; `to_forensic_model(image)` | `ForensicModel` — daqui em diante nada de MFT |
| `ntfs/investigation_entry.rs` | `InvestigationEntry` | `to_forensic_entry(spc)`: status dos flags MFT (`MFT_RECORD_IN_USE` → Deleted, `FILE_ATTRIBUTE_SYSTEM` → System); `sector_start = lcn * spc`; gera `physical_location` e `content_layout` (segments Physical/Sparse/Inline) | `ForensicEntry` |

### Camada do modelo (sem bytes)

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `forensic/model.rs` | entradas do parser | `ForensicModel { source, records_investigated, entries }`; `ForensicEntry` agrupa por *significado forense* (identity/hierarchy/metadata/allocation/physical_location/content_layout) | modelo independente de filesystem |
| `forensic/tree.rs` | `ForensicModel` | `ForensicTree::from_model` constrói a hierarquia por `parent_id` (raízes: sem pai, pai=si mesmo, ou pai não descoberto) | árvore navegável (objetos, não bytes) |

### Camada de aplicação (casos de uso, sem bytes)

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `app/inspection.rs` | caminho da imagem | `inspect_image`: abre `ImageReader` → `PartitionTableDetector::parse` → por partição: range seguro (`partition_end <= size`) → `detect` → **gate `is_supported()`** → `open_ntfs` → `investigate` → `to_forensic_model` → `ForensicTree::from_model`. Sem tabela de partição: `detect_at(0)` | `InspectionResult { image, size, partition_table, partitions, filesystems, models, trees }` |
| `app/recovery.rs` | caminho da imagem | `recover_object`/`recover_deleted_files`/`recover_all`; `create_engine` usa `partition_offset = start_sector * 512`; calcula SHA-256 do recuperado, compara com o de referência e grava o arquivo (sufixo por Object ID se colidir) | `Vec<RecoveredFile>` (entry + recovery + output_path + hashes + `HashComparison`) |

### Camada de interfaces (H4 — irmãs)

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `forensis-cli/src/main.rs` | argv (clap) | comandos `inspect`/`tree`/`recover`; formata modelo/árvore/resultado em texto com cores | saída para stdout |
| `forensis-tui/src/main.rs` | argv | `inspect_image` → `run_tui`; estados (source → browser → inspection → recovery), `recover_object` para diretórios `.working-<N>` | render ratatui |

### Camada de retorno do byte (V3 — descida)

| Arquivo | Entrada | O que faz | Saída |
| --- | --- | --- | --- |
| `recovery/engine.rs` | `Readable` + `ForensicEntry` | `PhysicalRecoveryEngine::recover`: `content_layout` é autoritativo → para cada segmento: `Physical` relê no disco (`region_offset`: offset explícito ou `partition_offset + sector_start*512`; `region_size = sector_count*512`), `Sparse` → zeros, `Inline` → dados carregados; trunca ao `real_size`; fallback legado por `physical_location` | `RecoveryResult` |
| `recovery/result.rs` | — | `RecoveryResult { entry, recovered, data, original_sha256, physical_location, reason }` | resultado recuperado/falho |
| `recovery/mod.rs` | — | declara o contrato: a camada **não depende** de NTFS/EXT4/FAT32 | — |

## O caminho do byte — fórmulas reais

Todas as posições derivam de quatro contas (todas com aritmética checked):

```text
partition_offset  = start_sector * 512                       (app/inspection.rs, app/recovery.rs)
mft_offset        = partition_offset + mft_cluster * spc * bps   (ntfs/mft_reader.rs)
run_lcn_offset    = partition_offset + lcn * bytes_per_cluster   (ntfs/data_run_reader.rs)
region_offset     = offset explícito  OU  partition_offset + sector_start * 512   (recovery/engine.rs)
region_size       = sector_count * 512
sector_start      = lcn * sectors_per_cluster                 (ntfs/investigation_entry.rs)
```

O byte entra cru por `read_at`, sobe como estrutura (setor → partição →
tipo de FS → geometria → registro → attributes → `ForensicEntry`) e,
na recuperação, **desce de novo** pelas mesmas contas até `read_at`
para virar conteúdo.

### Round-trip do byte na recuperação

```text
                    ForensicEntry (content_layout: segments)
                              |
      Physical segment        |        Sparse segment    Inline segment
                              |
   partition_offset + sector*512   ->      zeros           dados na memória
                              |
                              v
                    bytes reordenados na ordem lógica
                              |
              +---------------+----------------+
              v                                v
       SHA-256 do recuperado           compare (original)
              |
              v
      forensis-recovery/<ticket>/<nome>  (+ hash comparison)
```

É por isso que o `recover` consegue remontar arquivos **fragmentados** e
**esparsos**: o layout lógico (`logical_cluster_start` + ordem dos
segmentos) preserva a ordem original dos bytes, mesmo que os runs
físicos estejam espalhados.

## Guia de extensão: exfat / ext3

Como o fluxo é vertical com dois leques horizontais, adicionar um
filesystem toca apenas os 4 pontos abaixo — tudo que fica **acima** do
modelo (app recovery + interfaces) não muda:

1. **Detecção** — `filesystem/detector.rs::detect_at`:
   - exFAT precisa da assinatura `"EXFAT   "` em `[3..11]` do boot sector
     (exFAT não tem superblock análogo ao ext — é 100% boot sector);
   - ext3 compartilha o mesmo superblock do ext4 (magic `0xEF53`);
     para separar ext3 de ext4 use os campos de *features*
     (`compat/ro_compat`).
2. **Gate de suporte** — `FileSystemType::is_supported()`: habilitar o
   novo `Self::ExFat` (hoje `matches!(self, Self::Ntfs | Self::Ext4 | Self::Fat32)`).
3. **Ponto de plug no pipeline** — `app/inspection.rs`, nos dois
   `match filesystem` (caso com partição, linhas ~153, e sem partição,
   linhas ~228): adicionar `FileSystemType::ExFat => { ... }` seguindo o
   padrão dos existentes (abrir → investigar → `to_forensic_model` → tree).
4. **O parser irmão** — `filesystem/<fs>/` deve espelhar
   `ntfs/boot_sector.rs + investigation.rs`:
   - ter um `XxxFileSystem::parse(reader, partition_offset)` que leia a
     geometria;
   - produzir uma investigação própria terminando em
     `to_forensic_model(image)` emitindo `ForensicEntry` **com
     `content_layout`** (segments `Physical`/`Sparse`/`Inline`).

O `PhysicalRecoveryEngine` **não precisa de mudanças**: ele só conhece os
segments do `content_layout`. Use `fat32/` como o modelo de referência
(é a implementação mais recente e completa de um "parser irmão").

## Design principles

1. **Modelo forense independente de filesystem.** Parsers produzem
   `ForensicEntry` genéricos; recuperação e interfaces consomem apenas
   conceitos genéricos. Novos filesystems estendem **só o lado produtor**
   (H2), nunca o lado consumidor.
2. **Abstração por traits.** `Readable` unifica arquivo e device,
   `PartitionTableReader` esconde MBR/GPT, `RecoveryEngine` é puramente
   dirigido pelo modelo.
3. **Tipos fortes.** Offset, tamanho, setor e cluster são newtypes.
4. **Parsing defensivo.** GPT limita tamanho/contagem, resolução de
   caminho NTFS protege contra ciclos, toda conta de disco/partição usa
   aritmética checked.
5. **Encapsulamento de SO.** Block device Linux fica confinado a
   `image_reader.rs` e `app/source.rs`, com fallback não-Linux.

## Limitações atuais

- Offsets de partição assumem setores lógicos de 512 B.
- O espelho da MFT (`$MFTMirr`) nunca é lido (sem fallback p/ `$MFT` corrompida).
- Timestamps NTFS são parseados mas não propagados ao modelo.
- Vários parsers construídos mas não ligados ao pipeline (`$Bitmap`,
  `$UpCase`, `$Secure`, `$BadClus`, `$LogFile`, `$AttrDef`, `INDEX_ALLOCATION`).
- `recover all` é hoje alias de `recover deleted`; carving é trabalho futuro.
- Recuperação é em memória; objetos muito grandes não são streamados.
- APIs mortas (`DiskReader`, `Disk`/`DiskKind`) substituídas por `Readable`.

Itens rastreados em [filesystem-roadmap](filesystem-roadmap.md) e nas
[notas de implementação NTFS](ntfs/implementation.md).