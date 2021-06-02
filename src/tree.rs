use std::{usize, vec};

use crate::{
    hash::{hash_to_str, HashSM3},
    proof::Proof,
};

pub struct MerkleTree {
    pub nodes: Vec<Vec<Vec<u8>>>, // 分层存储节点
    pub leaves: usize,            // 叶子节点数量
    pub height: usize,            // 树的高度
    pub blocksize: usize,         // 数据块的大小
}

// 求两个节点合并后的哈希值，如果只剩最后一个节点则返回它自己
// 在递归生成树时使用
fn combined_hash(v: &Vec<Vec<u8>>, index: usize) -> Vec<u8> {
    let mut left = v.get(index).unwrap().clone();
    let right = v.get(index + 1);
    match right {
        Some(v) => {
            left.append(&mut v.clone());
            left.sm3()
        }
        None => left,
    }
}

impl MerkleTree {
    pub fn new<T: HashSM3>(data: &Vec<T>, blocksize: usize) -> MerkleTree {
        // 如果数据为空
        if data.is_empty() {
            return MerkleTree {
                nodes: vec![],
                leaves: 0,
                height: 0,
                blocksize: 0,
            };
        }

        // 数据非空
        let leaves = data.len();
        let mut height = 0;
        let mut cur = Vec::with_capacity(leaves);
        let mut tree = vec![];
        // 先从所有数据中生成哈希值作为最底层的叶子节点
        for v in data {
            let leaf = v.sm3();
            cur.push(leaf);
        }

        // 递归地从下至上两两结合哈希值
        loop {
            let pre_size = cur.len();
            let size = pre_size / 2 + pre_size % 2;
            let mut next = Vec::with_capacity(size);

            for i in 0..size {
                next.push(combined_hash(&cur, i * 2));
            }

            // 当前一层哈希值全部处理完，转移到上一层
            tree.push(cur);
            height += 1;
            cur = next;

            if size == 1 {
                tree.push(cur);
                break;
            }
        }

        MerkleTree {
            nodes: tree,
            leaves,
            height,
            blocksize,
        }
    }

    // 返回根节点的哈希值
    pub fn root_hash(&self) -> Vec<u8> {
        self.nodes.get(self.height).unwrap().get(0).unwrap().clone()
    }

    // 两棵树是否相同(结构，根哈希)
    pub fn eq(&self, other: &MerkleTree) -> bool {
        self.struct_eq(other) && self.root_hash().eq(&other.root_hash())
    }

    // 两棵树在结构上是否相同
    pub fn struct_eq(&self, other: &MerkleTree) -> bool {
        self.height == other.height
            && self.blocksize == other.blocksize
            && self.leaves == other.leaves
    }

    // 比较两颗结构相同树，得到不同的数据块位置
    pub fn compare(&self, other: &MerkleTree) -> Vec<usize> {
        let mut result = Vec::new();

        if !self.struct_eq(other) {
            eprintln!("两棵树结构不同无法比较");
            return result;
        }

        // check中放置的为要检查的下标，从上至下对比两棵树
        let mut check = Vec::new();
        let mut index = self.height;
        check.push(0);

        while !check.is_empty() {
            let mut next = Vec::new();
            // 获得两棵树的一整层节点
            let level = self.nodes.get(index).unwrap();
            let level_other = other.nodes.get(index).unwrap();
            // check中还有要检查的下标
            while check.len() > 0 {
                let i = check.pop().unwrap();
                let o1 = level.get(i);
                let o2 = level_other.get(i);
                let flag = match o1 {
                    Some(v) => v.eq(o2.unwrap()),
                    None => true,
                };
                if !flag {
                    if index == 0 {
                        // 已经检查到最后一层
                        result.push(i);
                    } else {
                        // 当前检查的这个下标两边哈希值不等，要检查下一层的两个叶节点
                        next.push(i * 2);
                        next.push(i * 2 + 1);
                    }
                }
            }
            // 检查下一层
            check = next;
            if index == 0 {
                // 如果没有下一层就跳出循环
                break;
            } else {
                index -= 1;
            }
        }
        result.sort();
        result
    }

    // 用给定的下标从树中生成proof证明链
    pub fn gen_proof(&self, index: usize) -> (Vec<Vec<u8>>, Vec<bool>) {
        let mut result = Vec::new();
        let mut pos = Vec::new();
        let mut i = index;
        for level in &self.nodes {
            // 如果i整除2说明下标位于左子树中，把右节点哈希值加入proof中
            if i % 2 == 0 {
                i = i + 1;
            } else {
                i = i - 1;
            }
            match level.get(i) {
                Some(v) => {
                    result.push(v.clone());
                    pos.push(i % 2 == 0); // 记录当前proof链中数据是从左节点还是右节点得到
                }
                None => {}
            }
            i >>= 1;
        }

        (result, pos)
    }

    // 验证proof
    pub fn validate<T: HashSM3>(&self, proof: &Proof<T>) -> bool {
        (self.blocksize == proof.blocksize) && self.root_hash().eq(&proof.root_hash())
    }
}
