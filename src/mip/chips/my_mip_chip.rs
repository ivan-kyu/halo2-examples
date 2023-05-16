use std::marker::PhantomData;
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

#[derive(Debug, Clone)]
pub struct MyMerkleConfig {
    pub leaf: Column<Advice>,
    pub root: Column<Advice>,
    pub proof: Column<Advice>,
    pub hashed: Column<Advice>,
    pub instance: Column<Instance>,
    pub selector: Selector,
}

#[derive(Debug, Clone)]
pub struct MyMIPChip<F: FieldExt> {
    config: MyMerkleConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> MyMIPChip<F> {
    pub fn construct(config: MyMerkleConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> MyMerkleConfig {
        // let col_a = meta.advice_column();
        // let col_b = meta.advice_column();
        // let col_c = meta.advice_column();
        // let selector = meta.selector();
        // let instance = meta.instance_column();

        // meta.enable_equality(col_a);
        // meta.enable_equality(col_b);
        // meta.enable_equality(col_c);
        // meta.enable_equality(instance);

        // meta.create_gate("add", |meta| {
        //     //
        //     // col_a | col_b | col_c | selector
        //     //   a      b        c       s
        //     //
        //     let s = meta.query_selector(selector);
        //     let a = meta.query_advice(col_a, Rotation::cur());
        //     let b = meta.query_advice(col_b, Rotation::cur());
        //     let c = meta.query_advice(col_c, Rotation::cur());
        //     vec![s * (a + b - c)]
        // });


        // advice - private inputs
        // instance - public inputs
        // fixed - constants
        // selector - control gates (boolean)

        //
        // leaf  | proof | hashed | root | selector
        //  l        p       H              true
        //           p       H              true
        //           p       H      root    true
        //                          

        //
        // leaf  | proof | hashed | root | selector
        //  1        1       2              true
        //  2        1       3              true
        //  3        1       4        4     true
        //    

        let leaf = meta.advice_column(); // public
        let root = meta.advice_column(); // public
        let proof = meta.advice_column();  // public
        let hashed = meta.advice_column(); // public

        let instance = meta.instance_column(); // private
        let selector = meta.selector();

        meta.enable_equality(leaf);
        meta.enable_equality(root);
        meta.enable_equality(proof);
        meta.enable_equality(hashed);

        meta.create_gate("hash", |meta| {
            let s = meta.query_selector(selector);
            let leaf = meta.query_advice(leaf, Rotation::cur());
            let proof = meta.query_advice(proof, Rotation::cur());
            let hashed = meta.query_advice(hashed, Rotation::cur());
            vec![s * (leaf + proof - hashed)]
        });

        MyMerkleConfig {
            leaf,
            root,
            proof,
            hashed,
            instance,
            selector
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn assign_first_row(
        &self,
        mut layouter: impl Layouter<F>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>, AssignedCell<F, F>), Error> {

        layouter.assign_region(
            || "first row",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                let leaf = region.assign_advice_from_instance(
                    || "leaf",
                    self.config.instance,
                    0,
                    self.config.leaf,
                    0)?;

                let proof = region.assign_advice_from_instance(
                    || "proof",
                    self.config.instance,
                    0,
                    self.config.proof,
                    0)?;

                let hashed = region.assign_advice(
                    || "hashed",
                    self.config.hashed,
                    0,
                    || leaf.value().copied() + proof.value())?;

                Ok((leaf, proof, hashed))
            },
        )
    }

    pub fn assign_row(
        &self,
        mut layouter: impl Layouter<F>,
        prev_hashed: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "next row",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                prev_hashed.copy_advice(
                    || "leaf",
                    &mut region,
                    self.config.leaf,
                    0,
                )?;

                let proof = region.assign_advice_from_instance(
                    || "proof",
                    self.config.instance,
                    0,
                    self.config.proof,
                    0)?;

                let hashed = region.assign_advice(
                    || "hashed",
                    self.config.hashed,
                    0,
                    || prev_hashed.value().copied() + proof.value()
                )?;

                Ok(hashed)
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
}