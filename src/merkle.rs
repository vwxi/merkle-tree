use digest::{Digest, FixedOutputReset};
use std::{error::Error, fmt::Debug, marker::PhantomData};

pub struct MerkleTree<S: Digest + FixedOutputReset, const N: usize, const ND: usize> {
    tree: Vec<Vec<u8>>,
    _s: PhantomData<S>,
}

#[derive(Debug)]
enum ProofElementDirection {
    LEFT,
    RIGHT,
}

pub struct ProofElement<S: Digest + FixedOutputReset, const N: usize, const ND: usize> {
    hash: Vec<u8>,
    direction: ProofElementDirection,
    _s: PhantomData<S>,
}

impl<S: Digest + FixedOutputReset, const N: usize, const ND: usize> std::fmt::Debug
    for ProofElement<S, N, ND>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofElement")
            .field("hash", &self.hash)
            .field("direction", &self.direction)
            .finish()
    }
}

impl<S: Debug + Digest + FixedOutputReset, const N: usize, const ND: usize> Default
    for MerkleTree<S, N, ND>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Debug + Digest + FixedOutputReset, const N: usize, const ND: usize> MerkleTree<S, N, ND> {
    const LEAF_TAG: u8 = 1;
    const NODE_TAG: u8 = 2;

    #[must_use]
    pub fn new() -> Self {
        assert!(N < 8 * <S as Digest>::output_size());
        assert!(ND < 2 * 8 * <S as Digest>::output_size());

        Self {
            tree: vec![],
            _s: PhantomData,
        }
    }

    fn hash(data: &[u8]) -> Vec<u8> {
        let mut strategy = S::new();
        Digest::update(&mut strategy, data);

        let out = strategy.finalize_reset();

        out[..N].to_vec()
    }

    fn concat_hash(first: &[u8], second: &[u8]) -> Vec<u8> {
        let mut data: [u8; ND] = [0; ND];
        data[0..N].copy_from_slice(first);
        data[N..ND].copy_from_slice(second);

        Self::hash(&data)
    }

    fn tag_hash(tag: u8, data: &[u8]) -> Vec<u8> {
        let tag_block: Vec<u8> = vec![tag; N];
        let hashed_data = Self::hash(data);

        Self::concat_hash(&tag_block, &hashed_data)
    }

    // all inlined functions related to flat binary trees are from this article:
    // https://mmapped.blog/posts/22-flat-in-order-trees

    #[inline]
    fn last_set_bit(n: usize) -> usize {
        n - ((n - 1) & n)
    }

    #[inline]
    fn last_zero_bit(n: usize) -> usize {
        Self::last_set_bit(n + 1)
    }

    #[inline]
    fn pbt_parent(n: usize) -> usize {
        (Self::last_zero_bit(n) | n) & !(Self::last_zero_bit(n) << 1)
    }

    #[inline]
    fn pbt_left_child(n: usize) -> Option<usize> {
        if n & 1 == 1 {
            Some(n & !(Self::last_zero_bit(n) >> 1))
        } else {
            None
        }
    }

    #[inline]
    fn pbt_right_child(n: usize) -> Option<usize> {
        if n & 1 == 1 {
            Some((n | Self::last_zero_bit(n)) & !(Self::last_zero_bit(n) >> 1))
        } else {
            None
        }
    }

    #[inline]
    fn lpbt_root(size: usize) -> usize {
        ((size + 1).next_power_of_two() - 1) >> 1
    }

    #[inline]
    fn pbt_leftmost_leaf(n: usize) -> usize {
        n & (n + 1)
    }

    #[inline]
    fn lpbt_parent(n: usize, size: usize) -> Option<usize> {
        if n == Self::lpbt_root(size) {
            None
        } else {
            let p = Self::pbt_parent(n);
            Some(if p < size {
                p
            } else {
                Self::pbt_leftmost_leaf(n) - 1
            })
        }
    }

    #[inline]
    fn lpbt_right_child(n: usize, size: usize) -> Option<usize> {
        if n & 1 == 1 {
            let r = Self::pbt_right_child(n)?;

            Some(if r < size {
                r
            } else {
                n + 1 + Self::lpbt_root(size - n - 1)
            })
        } else {
            None
        }
    }

    fn lpbt_set(&mut self, leaf_pos: usize, data: &[u8]) -> Result<(), Box<dyn Error>> {
        if leaf_pos > (self.tree.len() / 2) {
            return Err("Leaf position out of bounds".into());
        }

        let pos = leaf_pos * 2;
        self.tree[pos].copy_from_slice(data);

        let mut parent = Self::lpbt_parent(pos, self.tree.len());
        if parent.is_none() {
            return Err("structural error".into());
        }

        while let Some(parent_pos) = parent {
            // update as hash of children
            if let (Some(left), Some(right)) = (
                Self::pbt_left_child(parent_pos),
                Self::lpbt_right_child(parent_pos, self.tree.len()),
            ) {
                let hash = {
                    let hashed_data = Self::concat_hash(&self.tree[left], &self.tree[right]);
                    Self::tag_hash(Self::NODE_TAG, &hashed_data)
                };

                self.tree[parent_pos].copy_from_slice(&hash[..]);
            } else {
                return Err("could not get children".into());
            }

            parent = Self::lpbt_parent(parent_pos, self.tree.len());
        }

        Ok(())
    }

    pub fn add(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        if self.tree.is_empty() {
            self.tree.push(Self::tag_hash(Self::LEAF_TAG, data));
        } else {
            self.tree.push(vec![0; N]);
            self.tree.push(vec![0; N]);

            self.lpbt_set(
                self.tree.len() / 2,
                Self::tag_hash(Self::LEAF_TAG, data).as_slice(),
            )?;
        }

        Ok(())
    }

    #[must_use]
    pub fn root(&self) -> Option<Vec<u8>> {
        self.tree.get(Self::lpbt_root(self.tree.len())).cloned()
    }

    fn create_proof_route(
        &self,
        idx: usize,
        hash: &[u8],
        route: &mut Vec<ProofElement<S, N, ND>>,
    ) -> bool {
        if self.tree[idx] == hash {
            return true;
        }

        if let (Some(left), Some(right)) = (
            Self::pbt_left_child(idx),
            Self::lpbt_right_child(idx, self.tree.len()),
        ) {
            {
                route.push(ProofElement {
                    hash: self.tree[right].clone(),
                    direction: ProofElementDirection::RIGHT,
                    _s: PhantomData,
                });

                let new_sz = route.len();

                if self.create_proof_route(left, hash, route) {
                    return true;
                }

                route.remove(new_sz - 1);
            }

            {
                route.push(ProofElement {
                    hash: self.tree[left].clone(),
                    direction: ProofElementDirection::LEFT,
                    _s: PhantomData,
                });

                let new_sz = route.len();

                if self.create_proof_route(right, hash, route) {
                    return true;
                }

                route.remove(new_sz - 1);
            }
        }

        false
    }

    pub fn create_proof(&self, data: &[u8]) -> Option<Vec<ProofElement<S, N, ND>>> {
        let hash = Self::tag_hash(Self::LEAF_TAG, data);
        let mut route = vec![];

        let root = Self::lpbt_root(self.tree.len());
        if self.create_proof_route(root, hash.as_slice(), &mut route) {
            route.reverse();
            Some(route)
        } else {
            None
        }
    }

    pub fn verify_proof(data: &[u8], proof: &Vec<ProofElement<S, N, ND>>, to_match: &[u8]) -> bool {
        let hash = Self::tag_hash(Self::LEAF_TAG, data);
        let generated = proof.iter().fold(hash, |acc, e| {
            Self::tag_hash(
                Self::NODE_TAG,
                &match e.direction {
                    ProofElementDirection::LEFT => {
                        Self::concat_hash(e.hash.as_slice(), acc.as_slice())
                    }
                    ProofElementDirection::RIGHT => {
                        Self::concat_hash(acc.as_slice(), e.hash.as_slice())
                    }
                },
            )
        });

        generated.iter().eq(to_match)
    }
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::MerkleTree;

    type Tree = MerkleTree<Sha256, 32, 64>;

    #[test]
    fn add() {
        let mut tree = Tree::new();

        assert!(tree.add(&[0x01]).is_ok());
        assert!(tree.add(&[0x02]).is_ok());
        assert!(tree.add(&[0x03]).is_ok());
        assert!(tree.add(&[0x04]).is_ok());
        assert!(tree.add(&[0x05]).is_ok());

        let root = tree.root().unwrap();
        let proof = tree.create_proof(&[0x04]).unwrap();

        assert!(Tree::verify_proof(&[0x04], &proof, &root));
    }
}
