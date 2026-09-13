# Validation fixtures

The `lab/` directory holds raw forensic disk images used by the
integration tests and the man page examples. These images are **not
tracked by git** because they are large (more than 100 MiB each) and are
generated locally.

`cargo test --workspace` runs everywhere: tests that need a real image
skip themselves when the image is absent and print why.

The examples in `docs/forensis-cli.1` assume the images exist in `lab/`.
To regenerate them, follow the procedures below.

## NTFS

Own `lab/ntfs/disk.img` and `lab/ntfs-realistic/disk-fragmented.img`
created with a Windows/Ubuntu tool during local development. They contain
deleted and fragmented NTFS objects, used by:

- `crates/forensis-core/tests/ntfs_data_run_reader_test.rs`
- `crates/forensis-core/tests/ntfs_data_run_reader_attribute_test.rs`
- `crates/forensis-app/tests/recovery_real_image_test.rs`

## ext4

No root privileges are required. Build a whole-image ext4 fixture with
`mkfs.ext4` and populate it with `debugfs`:

```sh
mkdir -p lab/ext4-validation
cd lab/ext4-validation

dd if=/dev/zero of=disk-ext4.img bs=1M count=32 status=none
mkfs.ext4 -q -F disk-ext4.img

cat > cmds.txt <<'EOF'
mkdir /testes
mkdir /testes/nivel1
write <sourcedir>/arquivo-a.txt /testes/nivel1/arquivo-a.txt
mkdir /testes/nivel1/nivel2
write <sourcedir>/arquivo-b.txt /testes/nivel1/nivel2/arquivo-b.txt
mkdir /testes/outro
write <sourcedir>/arquivo-d.txt /testes/outro/arquivo-d.txt
write <sourcedir>/raiz.txt /testes/raiz.txt
mkdir /documentos
write <sourcedir>/fora-do-escopo.txt /documentos/fora-do-escopo.txt
write <sourcedir>/vivo.txt /testes/subvivo.txt
write <sourcedir>/boot.txt /boot.txt
symlink /testes/novo-link /testes/nivel1/arquivo-a.txt
EOF

debugfs -w -f cmds.txt disk-ext4.img
```

To create the deleted state, record the inode of each file to delete with
`debugfs -R "stat <inode>" ...`, then:

```sh
cat > del.txt <<'EOF'
unlink /testes/nivel1/arquivo-a.txt
unlink /testes/nivel1/nivel2/arquivo-b.txt
unlink /testes/outro/arquivo-d.txt
unlink /testes/raiz.txt
unlink /documentos/fora-do-escopo.txt
set_inode_field <N> dtime <epoch>
set_inode_field <N> links_count 0
EOF

debugfs -w -f del.txt disk-ext4.img
```

A Linux deletion keeps the inode's extent tree intact, which is exactly
the state `recover deleted` is designed to handle. See the Forensis
ext4 unit tests
(`crates/forensis-core/src/filesystem/ext4/`) for the investigated
semantics.

### MBR-partitioned variant

Wrap the whole-image ext4 behind an MBR partition starting at sector
2048 to exercise the partition-offset path:

```sh
python3 - <<'EOF'
import struct
ext = open('disk-ext4.img', 'rb').read()
count = len(ext) // 512
n = 4096 + count
with open('disk-mbr.img', 'wb') as f:
    f.write(b'\x00' * (2048 * 512))
    f.write(ext)
    f.write(b'\x00' * (n * 512 - 2048 * 512 - len(ext)))
img = bytearray(open('disk-mbr.img', 'rb').read())
o = 446
img[o + 0] = 0x80
img[o + 4] = 0x83
struct.pack_into('<I', img, o + 8, 2048)
struct.pack_into('<I', img, o + 12, count)
img[510:512] = b'\x55\xaa'
open('disk-mbr.img', 'wb').write(img)
EOF
```

Physical sectors reported by Forensis are relative to the start of the
partition, on both the whole-image and the MBR variants.

## FAT32

Build a whole-image FAT32 fixture with `mkfs.fat` and populate it with
mtools (`mmd`, `mcopy`, `mdel`). Prepared content can be staged on disk
and copied in:

```sh
mkdir -p lab/fat32-validation
cd lab/fat32-validation

mkfs.fat -C -F 32 -n EVID008 disk-fat32.img 65536   # 64 MiB

mmd -i disk-fat32.img  ::/dir1
mmd -i disk-fat32.img  ::/dir1/dir2
mcopy -i disk-fat32.img <sourcedir>/raiz.txt       ::/
mcopy -i disk-fat32.img <sourcedir>/leitura-geral.txt ::/dir1/
mcopy -i disk-fat32.img <sourcedir>/relatorio-final-2026.txt ::/dir1/dir2/
mcopy -i disk-fat32.img <sourcedir>/lista-equipamentos.txt  ::/dir1/dir2/
mcopy -i disk-fat32.img <sourcedir>/apagado.txt    ::/
mcopy -i disk-fat32.img <sourcedir>/confidencial-removido.txt ::/dir1/
mcopy -i disk-fat32.img <sourcedir>/excluido.txt   ::/dir1/dir2/
mcopy -i disk-fat32.img <sourcedir>/filler.bin     ::/
```

### Deleted state with a residual FAT chain

`mdel` marks the directory entry `0xE5` (kept along with the start
cluster and size) but it **clears the FAT chain**. To reproduce the
forensic artifact the FAT32 recovery is designed for — a deleted file
whose cluster chain is still recorded — delete the files and then
rewrite the residual chain directly in the FAT:

```sh
mdel -i disk-fat32.img ::/apagado.txt
mdel -i disk-fat32.img ::/confidencial-removido.txt
mdel -i disk-fat32.img ::/dir1/dir2/excluido.txt
mdel -i disk-fat32.img ::/filler.bin

python3 - <<'EOF'
import struct
img = 'disk-fat32.img'
d = bytearray(open(img, 'rb').read())
rsv = 32                      # BPB_RsvdSecCnt @ 0x0E
fatsz = struct.unpack('<I', d[0x24:0x28])[0]

def set_entry(copy, cluster, value):
    off = (rsv + copy * fatsz) * 512 + cluster * 4
    d[off:off + 4] = struct.pack('<I', value)

def keep_chain(start, clusters):
    for i in range(clusters - 1):
        set_entry(0, start + i, start + i + 1)
        set_entry(1, start + i, start + i + 1)
    set_entry(0, start + clusters - 1, 0x0FFFFFF8)
    set_entry(1, start + clusters - 1, 0x0FFFFFF8)

keep_chain(221, 1)      # apagado.txt (1 sector/cluster)
keep_chain(223, 1)      # excluido.txt
keep_chain(224, 4096)   # filler.bin (2 MiB)
open(img, 'wb').write(d)
EOF
```

The exact start clusters above hold only for this fixture layout; read
them from the `0xE5` directory entries (`start` at offsets 0x1A/0x14
low/high) instead of hard-coding them when building a new one.

### MBR-partitioned variant

Wrap the whole-image FAT32 behind an MBR partition of type `0x0C`
started at sector 2048 (see the ext4 variant above; use `0x0C` and the
FAT32 sector count).

Validated by:

- `crates/forensis-app/tests/recovery_real_image_test.rs` (FAT32
  whole-image and MBR-partitioned recovery, skip when `lab/` is absent).