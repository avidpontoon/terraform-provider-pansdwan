package main

import (
	"github.com/avidpontoon/terraform-provider-pan-sdwan/pan_sdwan"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: pan_sdwan.Provider,
	})
}
