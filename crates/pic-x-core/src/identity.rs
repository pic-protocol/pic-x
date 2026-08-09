//! ProductIdentity class: the branding a binary stamps on the surfaces its users see.
//!
//! No crate in this workspace hardcodes a product name, tagline, or ASCII art. The binary supplies
//! them, which is what lets a different binary be a different product while reusing the same crates.

/// The name, wording, and artwork a binary presents as.
///
/// Every value is `&'static str`: what a build calls itself is decided when it is compiled, not when
/// it is run, and the command-line parser needs the strings to outlive the parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductIdentity {
    binary_name: &'static str,
    product_name: &'static str,
    tagline: &'static str,
    about: &'static str,
    art: &'static str,
}

impl ProductIdentity {
    /// Builds the identity a binary presents as.
    ///
    /// * `binary_name` — the executable name shown in usage text and diagnostics.
    /// * `product_name` — the full product name rendered by both banner modes.
    /// * `tagline` — the single line rendered under the product name.
    /// * `about` — the one-line description shown by `--help`.
    /// * `art` — the ASCII art the full banner renders above the startup metadata.
    pub fn new(
        binary_name: &'static str,
        product_name: &'static str,
        tagline: &'static str,
        about: &'static str,
        art: &'static str,
    ) -> Self {
        Self {
            binary_name,
            product_name,
            tagline,
            about,
            art,
        }
    }

    /// Returns the executable name shown in usage text and diagnostics.
    pub fn binary_name(&self) -> &'static str {
        self.binary_name
    }

    /// Returns the full product name.
    pub fn product_name(&self) -> &'static str {
        self.product_name
    }

    /// Returns the product tagline.
    pub fn tagline(&self) -> &'static str {
        self.tagline
    }

    /// Returns the one-line description shown by `--help`.
    pub fn about(&self) -> &'static str {
        self.about
    }

    /// Returns the ASCII art rendered by the full banner.
    pub fn art(&self) -> &'static str {
        self.art
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ProductIdentity {
        ProductIdentity::new(
            "demo-x",
            "Demo X",
            "A tagline",
            "Demo X command line",
            "<art>",
        )
    }

    #[test]
    fn test_every_value_reads_back_as_supplied() {
        let identity = identity();

        assert_eq!(identity.binary_name(), "demo-x");
        assert_eq!(identity.product_name(), "Demo X");
        assert_eq!(identity.tagline(), "A tagline");
        assert_eq!(identity.about(), "Demo X command line");
        assert_eq!(identity.art(), "<art>");
    }
}
