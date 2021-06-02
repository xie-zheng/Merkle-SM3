use crate::{
    hash::{hash_to_str, HashSM3},
    tree::MerkleTree,
};

pub struct Proof<T: HashSM3> {
    pub chain: Vec<Vec<u8>>,  // 认证哈希串
    pub pos_chain: Vec<bool>, // true表示这个哈希值位于左侧节点
    pub data: T,              // 要验证的数据块
    pub index: usize,         // 验证的数据块下标
    pub blocksize: usize,     // 数据块大小
    pub roothash: Vec<u8>,    // 利用proof链生成的根哈希
}

impl<T: HashSM3> Proof<T> {
    pub fn new(tree: &MerkleTree, data: T, index: usize, blocksize: usize) -> Proof<T> {
        // 从树中得到一个proof数据链以及相应的位置链
        let (chain, pos_chain) = tree.gen_proof(index);
        let mut result = Proof {
            chain,
            pos_chain,
            data,
            index,
            blocksize,
            roothash: vec![],
        };
        result.cal_root_hash();
        result
    }

    pub fn cal_root_hash(&mut self) {
        let mut hash = self.data.sm3();
        let mut i: usize = 0;
        for h in &self.chain {
            let pos = *self.pos_chain.get(i).unwrap();
            i += 1;
            let mut other = h.clone();

            // 如果pos为true，说明链中节点为左节点，把之前的数据拼接到链中
            // 数据之后，否则把链中数据拼接到之前的数据后
            if pos {
                other.append(&mut hash);
                hash = other;
            } else {
                hash.append(&mut other);
            }
            hash = hash.sm3();
        }
        self.roothash = hash;
    }

    pub fn root_hash(&self) -> Vec<u8> {
        return self.roothash.clone();
    }

    // 从数据节点开始从上运算输出根哈希
    // 展示这整个过程
    pub fn show(&self) {
        // 数据块的哈希
        let mut hash = self.data.sm3();
        println!(
            "====PROOF====\n数据块大小: {}  数据块下标: {}\n数据块哈希值: {}",
            self.blocksize,
            self.index,
            hash_to_str(&hash),
        );

        for (i, proof) in self.chain.iter().enumerate() {
            let pos = if self.pos_chain.get(i).unwrap().clone() {
                String::from("左节点")
            } else {
                String::from("右节点")
            };
            println!("proof{} {}: {}", i, pos, hash_to_str(proof));
        }

        println!("====生成根哈希过程====");
        let mut i: usize = 0;
        for h in &self.chain {
            let pos = *self.pos_chain.get(i).unwrap();
            i += 1;
            let mut other = h.clone();

            // 如果pos为true，说明链中节点为左节点，把之前的数据拼接到链中
            // 数据之后，否则把链中数据拼接到之前的数据后
            if pos {
                println!(
                    "左节点哈希值: {}\n右节点哈希值: {}",
                    hash_to_str(&other),
                    hash_to_str(&hash)
                );
                other.append(&mut hash);
                hash = other;
            } else {
                println!(
                    "左节点哈希值: {}\n右节点哈希值: {}",
                    hash_to_str(&hash),
                    hash_to_str(&other)
                );
                hash.append(&mut other);
            }
            hash = hash.sm3();
            println!("组合后哈希值: {}\n", hash_to_str(&hash));
        }
        println!("根节点哈希值: {}\n====================", hash_to_str(&hash));
    }
}
