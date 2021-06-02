use std::fs;

use crate::hash::{hash_to_str, HashSM3};
use crate::proof::Proof;
use crate::tree::MerkleTree;

// 把文件数据切分为大小为'blocksize'字节的数据块组
pub fn data_to_blocks(data: &Vec<u8>, blocksize: usize) -> Vec<Vec<u8>> {
    let mut data_blocks = Vec::new();
    let mut counter: usize = 0; // counter记录已经往临时数组里放了多少数据
    let mut temp: Vec<u8> = Vec::with_capacity(blocksize); // 容积为blocksize的临时数组
    for v in data {
        // 存入单个字节
        temp.push(*v);
        counter += 1;

        // 存满blocksize字节后，把当前数据块放入data_blocks中
        // 清空临时数据块中数据
        if counter == blocksize {
            counter = 0;
            data_blocks.push(temp.clone());
            temp.clear();
        }
    }
    // 数据末尾长度小于blocksize的剩余数据
    data_blocks.push(temp);
    data_blocks
}

pub struct Config {
    pub operator: String,
    pub file1: String,
    pub file2: String,
    pub blocksize: usize,
    pub index: usize,
}

impl Config {
    fn new(args: &Vec<String>) -> Config {
        if args.len() == 5 {
            // ./merkle compare file1 file2 blocksize
            Config {
                operator: args[1].clone(),
                file1: args[2].clone(),
                file2: args[3].clone(),
                blocksize: args[4].clone().parse().unwrap(),
                index: 0,
            }
        } else if args.len() == 6 {
            // ./merkle proof file1(验证proof) file2(生成proof) blocksize index
            Config {
                operator: args[1].clone(),
                file1: args[2].clone(),
                file2: args[3].clone(),
                blocksize: args[4].clone().parse().unwrap(),
                index: args[5].clone().parse().unwrap(),
            }
        } else {
            eprintln!(
                "./merkle [compare file1 file2 blocksize | proof file1(验证proof) file2(生成proof) blocksize index]"
            );
            std::process::exit(1);
        }
    }
}

pub fn run(args: Vec<String>) {
    let config = Config::new(&args);

    // true代表接下来进行两个文件的比较，false表示利用文件2验证文件1中的某个数据块是否存在于文件2中
    let flag = config.operator.eq(&String::from("compare"));

    // 读取文件
    let f1 = data_to_blocks(&fs::read(config.file1).unwrap(), config.blocksize);
    let f2 = data_to_blocks(&fs::read(config.file2).unwrap(), config.blocksize);
    // 构建Merkle树
    let tree1 = MerkleTree::new(&f1, config.blocksize);
    let tree2 = MerkleTree::new(&f2, config.blocksize);

    if flag {
        // compare
        let diffent = tree1.compare(&tree2);

        println!(
            "树1根哈希: {}\n树2根哈希: {}",
            hash_to_str(&tree1.root_hash()),
            hash_to_str(&tree2.root_hash())
        );

        println!(
            "对比得到不同的数据块为(blocksize: {}) \n{:?}",
            tree1.blocksize, diffent
        )
    } else {
        // proof
        if config.index >= tree2.leaves {
            eprintln!(
                "生成proof失败， 下标({})越界， 树2只有{}个数据块",
                config.index, tree2.leaves
            );
            std::process::exit(1);
        }
        println!("利用树2生成下标为{}处的Proof： ", config.index);

        // 生成proof
        let proof = Proof::new(
            &tree2,
            f1.get(config.index).unwrap().clone(),
            config.index,
            config.blocksize,
        );
        proof.show();
        println!(
            "目标树的根杂凑值为{}\n验证proof结果 {}",
            hash_to_str(&tree2.root_hash()),
            tree2.validate(&proof)
        )
    }
}
