# merkle-tree

A merkle tree implementation in Rust. The routines use a flat in-order binary tree defined in [this blog post](https://mmapped.blog/posts/22-flat-in-order-trees). Supports arbitrary hash sizes, inclusion proof generation/validation and (most likely) second preimage attack mitigation.  

This project is still in progress.

## Examples

```rust
type Tree = MerkleTree<Sha256, 32, 64>;

let mut tree = Tree::new();

tree.add(&[0x01])?;
tree.add(&[0x02])?;
tree.add(&[0x03])?;
tree.add(&[0x04])?;
tree.add(&[0x05])?;

let root = tree.root().unwrap();
let proof = tree.create_proof(&[0x04]).unwrap();

assert!(Tree::verify_proof(&[0x04], &proof, &root));
```
