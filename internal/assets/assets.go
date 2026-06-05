package assets

import "embed"

// FS contains the runtime files envd needs after installation. The CLI may use
// checked-out files during development, but installed binaries must not depend
// on a repo checkout.
//
//go:embed containers/*/* gateway/config.template.json
var FS embed.FS
