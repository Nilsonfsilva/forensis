use crate::error::ForensisError;
use crate::result::Result;
use crate::traits::Readable;

use super::{Ext4Extent, Ext4ExtentHeader, Ext4ExtentIndex, Ext4Inode, Ext4Reader, Ext4Superblock};

/// Maximum depth of the EXT4 extent tree.
///
/// A larger depth on disk indicates a corrupted structure.
/// Navigation stops at this bound to protect the investigation
/// against infinite recursion.
const MAX_EXTENT_TREE_DEPTH: u16 = 5;

/// Resolves the complete extent list of an inode.
///
/// The extent tree may be stored entirely inside the inode
/// `i_block` area (depth zero) or may span multiple external
/// index and leaf blocks (depth greater than zero).
///
/// The returned extents are sorted by logical block number.
///
/// When the inode does not contain a valid extent tree, an
/// empty list is returned. This is the case for fast symbolic
/// links, whose target is stored directly in `i_block`.
pub fn resolve_extents<R: Readable>(
    reader: &mut Ext4Reader<R>,
    superblock: &Ext4Superblock,
    inode: &Ext4Inode,
) -> Result<Vec<Ext4Extent>> {
    let root = inode.i_block();

    let header = match Ext4ExtentHeader::parse(root) {
        Ok(header) => header,
        Err(_) => return Ok(Vec::new()),
    };

    let mut extents = Vec::new();

    resolve_node(
        reader,
        superblock,
        root,
        header.depth().min(MAX_EXTENT_TREE_DEPTH),
        &mut extents,
    )?;

    extents.sort_by_key(|extent| extent.logical_block());

    Ok(extents)
}

/// Reads the extent entries of one leaf node.
fn read_leaf_entries(
    data: &[u8],
    header: &Ext4ExtentHeader,
    extents: &mut Vec<Ext4Extent>,
) -> Result<()> {
    let mut offset = Ext4ExtentHeader::SIZE;

    for _ in 0..header.entries() {
        if offset + Ext4Extent::SIZE > data.len() {
            return Err(ForensisError::InvalidFormat(
                "Input read buffer size".to_string(),
            ));
        }

        extents.push(Ext4Extent::parse(&data[offset..offset + Ext4Extent::SIZE])?);

        offset += Ext4Extent::SIZE;
    }

    Ok(())
}

/// Walks one extent tree node.
///
/// A depth of zero means the node directly contains extents.
/// A depth greater than zero means the node contains indexes
/// pointing to child nodes stored in external blocks.
fn resolve_node<R: Readable>(
    reader: &mut Ext4Reader<R>,
    superblock: &Ext4Superblock,
    data: &[u8],
    depth: u16,
    extents: &mut Vec<Ext4Extent>,
) -> Result<()> {
    let header = match Ext4ExtentHeader::parse(data) {
        Ok(header) => header,
        Err(_) => return Ok(()),
    };

    if header.is_leaf() {
        return read_leaf_entries(data, &header, extents);
    }

    if depth == 0 {
        return Ok(());
    }

    let mut offset = Ext4ExtentHeader::SIZE;

    for _ in 0..header.entries() {
        if offset + Ext4ExtentIndex::SIZE > data.len() {
            return Err(ForensisError::InvalidFormat(
                "Input read buffer size".to_string(),
            ));
        }

        let index = Ext4ExtentIndex::parse(&data[offset..offset + Ext4ExtentIndex::SIZE])?;

        offset += Ext4ExtentIndex::SIZE;

        let child = reader.read_block(superblock, index.leaf_block())?;

        resolve_node(reader, superblock, &child, depth - 1, extents)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteOffset, ByteSize};

    /// In-memory evidence source for tests.
    struct MemorySource {
        data: Vec<u8>,
    }

    impl Readable for MemorySource {
        fn read_at(&mut self, offset: ByteOffset, buffer: &mut [u8]) -> Result<()> {
            let offset = offset.value() as usize;

            if offset >= self.data.len() {
                buffer.fill(0);
                return Ok(());
            }

            let end = (offset + buffer.len()).min(self.data.len());

            buffer[..end - offset].copy_from_slice(&self.data[offset..end]);

            buffer[end - offset..].fill(0);

            Ok(())
        }

        fn size(&self) -> ByteSize {
            ByteSize::new(self.data.len() as u64)
        }
    }

    /// Builds a superblock with the given block size.
    fn superblock(block_size_log: u32, block_count: u32) -> Ext4Superblock {
        let mut data = vec![0u8; 1024];

        data[0x38..0x3A].copy_from_slice(&Ext4Superblock::EXT4_MAGIC.to_le_bytes());

        data[0x18..0x1C].copy_from_slice(&block_size_log.to_le_bytes());

        data[0x04..0x08].copy_from_slice(&block_count.to_le_bytes());

        data[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes());

        data[0x28..0x2C].copy_from_slice(&16u32.to_le_bytes());

        data[0x20..0x24].copy_from_slice(&32u32.to_le_bytes());

        Ext4Superblock::parse(&data).unwrap()
    }

    /// Builds an inode whose `i_block` area is initialized
    /// with the given bytes.
    fn inode_with_block(block: &[u8]) -> Ext4Inode {
        let mut data = vec![0u8; 256];

        data[0x28..0x28 + block.len()].copy_from_slice(block);

        Ext4Inode::parse(&data).unwrap()
    }

    /// Builds an extent header plus one extent entry.
    #[allow(clippy::identity_op)]
    fn flat_tree(extents: &[(u32, u32, u16)]) -> Vec<u8> {
        let mut data = vec![0u8; Ext4ExtentHeader::SIZE + extents.len() * Ext4Extent::SIZE];

        data[0..2].copy_from_slice(&Ext4ExtentHeader::MAGIC.to_le_bytes());

        data[2..4].copy_from_slice(&(extents.len() as u16).to_le_bytes());

        data[4..6].copy_from_slice(&(extents.len() as u16).to_le_bytes());

        for (index, (logical, physical, length)) in extents.iter().enumerate() {
            let offset = Ext4ExtentHeader::SIZE + index * Ext4Extent::SIZE;

            data[offset..offset + 4].copy_from_slice(&logical.to_le_bytes());

            let raw_length = if *length >= 0x8000 {
                *length | 0x8000
            } else {
                *length
            };

            data[offset + 4..offset + 6].copy_from_slice(&raw_length.to_le_bytes());

            data[offset + 6..offset + 8].copy_from_slice(&0u16.to_le_bytes());

            data[offset + 8..offset + 12].copy_from_slice(&(physical & 0xFFFFFFFF).to_le_bytes());
        }

        data
    }

    #[test]
    fn resolves_flat_extent_tree() {
        let source = MemorySource {
            data: vec![0u8; 4096 * 8],
        };

        let sb = superblock(2, 8);

        let mut reader = Ext4Reader::new(source, 0);

        let inode = inode_with_block(&flat_tree(&[(0, 100, 4), (4, 200, 2)]));

        let extents = resolve_extents(&mut reader, &sb, &inode).unwrap();

        assert_eq!(extents.len(), 2);

        assert_eq!(extents[0].logical_block(), 0);
        assert_eq!(extents[0].physical_block(), 100);
        assert_eq!(extents[0].length(), 4);

        assert_eq!(extents[1].logical_block(), 4);
        assert_eq!(extents[1].physical_block(), 200);
        assert_eq!(extents[1].length(), 2);
    }

    #[test]
    fn returns_empty_for_non_tree_inode() {
        let source = MemorySource {
            data: vec![0u8; 4096],
        };

        let sb = superblock(2, 8);

        let mut reader = Ext4Reader::new(source, 0);

        let inode = inode_with_block(b"hello-symlink-target");

        let extents = resolve_extents(&mut reader, &sb, &inode).unwrap();

        assert!(extents.is_empty());
    }

    #[test]
    fn resolves_indexed_extent_tree() {
        /*
         * Root i_block contains an index node pointing to the
         * leaf block stored at physical block 5. The leaf block
         * contains the actual extent entries.
         */
        let mut root = vec![0u8; Ext4ExtentHeader::SIZE + Ext4ExtentIndex::SIZE];

        root[0..2].copy_from_slice(&Ext4ExtentHeader::MAGIC.to_le_bytes());

        root[2..4].copy_from_slice(&1u16.to_le_bytes());

        root[4..6].copy_from_slice(&1u16.to_le_bytes());

        root[6..8].copy_from_slice(&1u16.to_le_bytes());

        root[Ext4ExtentHeader::SIZE..Ext4ExtentHeader::SIZE + 4]
            .copy_from_slice(&0u32.to_le_bytes());

        root[Ext4ExtentHeader::SIZE + 4..Ext4ExtentHeader::SIZE + 8]
            .copy_from_slice(&5u32.to_le_bytes());

        let leaf = flat_tree(&[(0, 300, 16)]);

        let block_size = 4096usize;

        let mut image = vec![0u8; block_size * 8];

        image[block_size * 5..block_size * 5 + leaf.len()].copy_from_slice(&leaf);

        let source = MemorySource { data: image };

        let sb = superblock(2, 8);

        let mut reader = Ext4Reader::new(source, 0);

        let inode = inode_with_block(&root);

        let extents = resolve_extents(&mut reader, &sb, &inode).unwrap();

        assert_eq!(extents.len(), 1);

        assert_eq!(extents[0].logical_block(), 0);
        assert_eq!(extents[0].physical_block(), 300);
        assert_eq!(extents[0].length(), 16);
    }
}
