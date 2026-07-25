//! Cœur partagé GuatX (Plume ↔ Forge).
//!
//! Décision d'archi : « cœur partagé, produits séparés ». Le ~70 % commun (moteur de requête,
//! auth/host-guard, exécution read-only, packaging) vit ici ; Plume (SOC bleu) et la console Forge
//! (rouge) en dépendent. v0 extrait le moteur **soql** (pur `std`, zéro dépendance) ; les autres
//! primitives (auth argon2, host-guard, query-exec) remonteront ici quand les interfaces seront figées.
//!
//! Migration Plume = suite : le daemon Plume peut adopter `guatx_core::soql` à la place de son
//! compiler interne, sans réécriture (même API). La console Forge l'utilise déjà.

// SPI IA CONSEIL (advisory) — NL→SOQL. Derrière la feature `ai` (DÉFAUT OFF) : le build par
// défaut est byte-identique (mode-0), rien de la couche IA n'entre. Pur `std`, zéro dép nouvelle ; le
// module ne livre QUE le CONTRAT + helpers purs (les impls réseau/vendeur vivent dans le daemon).
#[cfg(feature = "ai")]
pub mod ai;
pub mod attack;
pub mod cim;
pub mod secret;
pub mod soql;
pub mod store;
pub mod ti;
