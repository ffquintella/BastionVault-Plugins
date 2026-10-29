//! `bastion-plugin-dbms-management`: the process the host spawns. All logic
//! is in the library; see `lib.rs`.

fn main() {
    bastion_plugin_sdk::process::run(bastion_plugin_dbms_management::Plugin::new())
}
