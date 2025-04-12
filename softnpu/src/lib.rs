// Copyright 2022 Oxide Computer Company
#![allow(clippy::too_many_arguments)]
#![allow(clippy::redundant_closure_call)]
#![allow(unexpected_cfgs)]

#[cfg(test)]
mod test;

p4_macro::use_p4!(p4 = "p4/sidecar-lite.p4", pipeline_name = "main");
