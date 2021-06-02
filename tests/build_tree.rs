#![cfg(test)]

extern crate merkle;
use std::fs;

use merkle::config::data_to_blocks;
use merkle::hash::hash_to_str;
use merkle::tree::MerkleTree;
#[test]
fn build_tree_1() {
    let source_data = fs::read("./files/f1.txt").unwrap();
    let block1 = data_to_blocks(&source_data, 1024);
    let tree = MerkleTree::new(&block1, 1024);
    assert_eq!(
        hash_to_str(&tree.root_hash()),
        "5a6315a4f58f18181e6db7ce764c6b8c9fa32298b1f818639c82d19be5ea6b29"
    );
}

#[test]
fn build_tree_2() {
    let source_data = fs::read("./files/f1.txt").unwrap();
    for i in 1..2049 {
        let block = data_to_blocks(&source_data, i);
        let tree = MerkleTree::new(&block, i);
    }
}
