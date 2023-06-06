use super::hash_2::{self, Hash2Chip, Hash2Config};
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::*,
    plonk::*,
    poly::Rotation,
};
use std::{marker::PhantomData, path, println};

#[derive(Debug, Clone)]
pub struct MyMIPConfigV2 {
    pub advice: [Column<Advice>; 3],
    pub bool_selector: Selector,
    pub swap_selector: Selector,
    pub instance: Column<Instance>,
    pub hash2_config: Hash2Config,
}

#[derive(Debug, Clone)]
pub struct MyMIPChipV2<F: FieldExt> {
    config: MyMIPConfigV2,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> MyMIPChipV2<F> {
    pub fn construct(config: MyMIPConfigV2) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> MyMIPConfigV2 {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();
        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(instance);

        // Enforces that c is either a 0 or 1.
        meta.create_gate("bool", |meta| {
            let s = meta.query_selector(bool_selector);
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * c.clone() * (Expression::Constant(F::from(1)) - c.clone())]
        });

        // Enforces that if the swap bit is on, l=b and r=a. Otherwise, l=a and r=b.
        meta.create_gate("swap", |meta| {
            let s = meta.query_selector(swap_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let l = meta.query_advice(col_a, Rotation::next());
            let r = meta.query_advice(col_b, Rotation::next());
            vec![
                s * (c * Expression::Constant(F::from(2)) * (b.clone() - a.clone())
                    - (l - a.clone())
                    - (b.clone() - r)),
            ]
        });

        MyMIPConfigV2 {
            advice: [col_a, col_b, col_c],
            bool_selector: bool_selector,
            swap_selector: swap_selector,
            instance: instance,
            hash2_config: Hash2Chip::configure(meta, [col_a, col_b, col_c], instance),
        }
    }

    pub fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        start_leaf: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "load private",
            |mut region| {
                region.assign_advice(|| "private input", self.config.advice[0], 0, || start_leaf)
            },
        )
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }

    pub fn merkle_prove(
        &self,
        mut layouter: impl Layouter<F>,
        start_leaf: &AssignedCell<F, F>,
        elements: &Vec<Value<F>>,
        indices: &Vec<Value<F>>,
    ) -> Result<AssignedCell<F, F>, Error> {

        let mut new_hash = self.merkle_prove_row(
            layouter.namespace(|| "merkle_prove_row_0"),
            start_leaf,
            elements[0],
            indices[0],
        )?;

        for i in 1..elements.len() {
            new_hash = self.merkle_prove_row(
                layouter.namespace(|| format!("merkle_prove_row_{}", i)),
                &new_hash,
                elements[i],
                indices[i],
            )?;
        }
        Ok(new_hash)
    }

    fn merkle_prove_row(
        &self,
        mut layouter: impl Layouter<F>,
        leafhash: &AssignedCell<F, F>,
        element: Value<F>,
        index: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        
        let (left, right) = layouter.assign_region(
            || "merkle_prove_row",
            |mut region| {
                // Row 0 (in the layout!!)
                // plot col 1
                leafhash.copy_advice(
                    || "leafhash", 
                    &mut region, 
                    self.config.advice[0], 
                    0)?;
                // plot col 2
                region.assign_advice(|| "element", self.config.advice[1], 0, || element)?;
                // plot col 3
                region.assign_advice(|| "index", self.config.advice[2], 0, || index)?;


                // plot col 4 ??
                self.config.bool_selector.enable(&mut region, 0)?;
                // plot col 5 ??
                self.config.swap_selector.enable(&mut region, 0)?;



                // Row 1 (in the layout!!)
                let leafhash_value = leafhash.value().map(|x| x.to_owned());

                let (mut l, mut r) = (leafhash_value, element);
                index.map(|x| {
                    (l, r) = if x == F::zero() { (l, r) } else { (r, l) };
                });

                // plot col 1 // offset 1
                let left = region
                    .assign_advice(
                        || "left", 
                        self.config.advice[0], 
                        1, 
                        || l)?;
                
                // plot col 2 // offset 1
                let right = region
                    .assign_advice(
                        || "right", 
                        self.config.advice[1], 
                        1, 
                        || r)?;

                Ok((left, right))
            },
        )?;

        print!("left: {:?}, right: {:?}", left.value(), right.value());

        let hash2_chip = Hash2Chip::construct(self.config.hash2_config.clone());

        let hashed = 
            hash2_chip.hash2(
                layouter.namespace(|| "hash 2"), 
                left, 
                right)?;

        println!("hashed: {:?}", hashed.value());

        Ok(hashed)
    }
}