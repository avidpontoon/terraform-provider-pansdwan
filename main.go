package main

import (
	pansdwan "github.com/avidpontoon/terraform-provider-pansdwan/internal/provider"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: pansdwan.Provider,
	})
}
