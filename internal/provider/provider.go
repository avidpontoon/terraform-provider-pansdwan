package pansdwan

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"hostname": {
				Type:     schema.TypeString,
				Required: true,
			},
			"username": {
				Type:     schema.TypeString,
				Required: true,
			},
			"password": {
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: true,
			},
			"skip_ssl_verification": {
				Type:      schema.TypeBool,
				Optional:  true,
				Sensitive: false,
				Default:   false,
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"pansdwan_sdwan_interface": resourceSDWANInterface(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

type APIClient struct {
	Host                string
	Username            string
	Password            string
	SkipSSLVerification bool
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return &APIClient{
		Host:                d.Get("hostname").(string),
		Username:            d.Get("username").(string),
		Password:            d.Get("password").(string),
		SkipSSLVerification: d.Get("skip_ssl_verification").(bool),
	}, nil
}
