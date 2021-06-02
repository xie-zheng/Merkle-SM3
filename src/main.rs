use merkle::{config::run, proof::Proof, sm3::sm3, tree::MerkleTree};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    run(args);
    // proof_test(args[1].clone().parse().unwrap());
}

fn ana(i: u32) {
    for _ in 0..i {
        sm3(&String::from("abc").as_bytes().to_vec());
    }
}

fn build(i: u32) {
    let data = merkle::config::data_to_blocks(&std::fs::read("files/1.txt").unwrap(), 2);
    for _ in 0..i {
        let tree: MerkleTree = MerkleTree::new(&data, 2);
    }
}

fn proof_test(i: u32) {
    let data = merkle::config::data_to_blocks(&std::fs::read("files/1.txt").unwrap(), 2);
    let tree: MerkleTree = MerkleTree::new(&data, 2);
    for _ in 0..i {
        let proof = Proof::new(&tree, data.get(0).unwrap().clone(), 0, 2);
    }
}
