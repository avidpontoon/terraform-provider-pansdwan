package pansdwan

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

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
			"pansdwan_l3_zone_entry":   resourceZoneEntry(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

type XMLAPIResponse struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Msg     struct {
		Lines []string `xml:"line"`
	} `xml:"msg"`
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

func buildHttpClient(skipVerify bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
		},
		Timeout: 30 * time.Second,
	}
}

func checkXMLResponse(body []byte) error {
	var xmlResp XMLAPIResponse
	if err := xml.Unmarshal(body, &xmlResp); err != nil {
		return fmt.Errorf("failed to unmarshal XML: %w. Response: %s", err, xmlResp)
	}
	if xmlResp.Status == "error" {
		return fmt.Errorf("PAN-OS API error: code=%s, message=%s. Response: %s", xmlResp.Code, xmlResp.Msg, xmlResp)
	}
	return nil
}
