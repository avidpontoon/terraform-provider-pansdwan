package pansdwan

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// XML Response Structs
type zoneInterfaces struct {
	XMLName xml.Name `xml:"response"`
	Text    string   `xml:",chardata"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Result  struct {
		Text       string `xml:",chardata"`
		TotalCount string `xml:"total-count,attr"`
		Count      string `xml:"count,attr"`
		Layer3     struct {
			Text   string   `xml:",chardata"`
			Member []string `xml:"member"`
		} `xml:"layer3"`
	} `xml:"result"`
}

func resourceZoneEntry() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceZoneEntryCreate,
		ReadContext:   resourceZoneEntryRead,
		UpdateContext: resourceZoneEntryUpdate,
		DeleteContext: resourceZoneEntryDelete,
		// Schema for the resource
		Schema: map[string]*schema.Schema{
			"template": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"interface": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"vsys": {
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func resourceZoneEntryCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*APIClient)
	// Construct the URL to create the sdwan interface
	req_url := fmt.Sprintf("https://%s/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/zone/entry[@name='%s']/network/layer3&element=<member>%s</member>",
		client.Host, url.QueryEscape(d.Get("template").(string)), url.QueryEscape(d.Get("vsys").(string)), url.QueryEscape(d.Get("name").(string)), url.QueryEscape(d.Get("interface").(string)))

	req, _ := http.NewRequest("GET", req_url, nil)
	apiKey, _ := getAPIKey(client.Host, client.Username, client.Password, client.SkipSSLVerification)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-PAN-KEY", apiKey)
	httpClient := buildHttpClient(client.SkipSSLVerification)

	resp, err := httpClient.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()
	// Read and check response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(err)
	}
	if resp.StatusCode != 200 {
		return diag.Errorf("Failed to add interface to Zone: %s", string(body))
	}
	// Catch failures in the response
	resp_err := checkXMLResponse(body)
	if resp_err != nil {
		return diag.FromErr(resp_err)
	}
	// Set the ID back to terraform as the name of the interface
	d.SetId(fmt.Sprintf("%s-%s-%s", d.Get("template").(string), d.Get("name").(string), d.Get("interface").(string)))
	// Return nothing as we only return the error if there was one
	return nil
}

func resourceZoneEntryRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*APIClient)
	// Construct the URL to get the zone interfaces
	req_url := fmt.Sprintf("https://%s/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/zone/entry[@name='%s']/network/layer3",
		client.Host, url.QueryEscape(d.Get("template").(string)), url.QueryEscape(d.Get("vsys").(string)), url.QueryEscape(d.Get("name").(string)))

	req, _ := http.NewRequest("GET", req_url, nil)
	apiKey, _ := getAPIKey(client.Host, client.Username, client.Password, client.SkipSSLVerification)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-PAN-KEY", apiKey)
	httpClient := buildHttpClient(client.SkipSSLVerification)

	resp, err := httpClient.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var zone_ifaces_xml_resp zoneInterfaces
	if err := xml.Unmarshal(body, &zone_ifaces_xml_resp); err != nil {
		panic(err)
	}
	// Catch failures in the response
	if resp.StatusCode != 200 {
		return diag.Errorf("Error getting zone interfaces: %s", string(body))
	}
	if zone_ifaces_xml_resp.Status == "error" {
		return diag.Errorf("Error getting zone interfaces: %s", string(body))
	}
	// Check if the interface exists
	if zone_ifaces_xml_resp.Code == "7" {
		// This means the interface does not exist set the ID to empty and return
		d.SetId("")
		return nil
	}
	// Set the resource data back to terraform
	d.Set("template", d.Get("template").(string))
	d.Set("name", d.Get("name").(string))
	d.Set("interface", d.Get("interface").(string))
	d.Set("vsys", d.Get("vsys").(string))
	// Return nothing as we only return the error if there was one
	return nil
}

func resourceZoneEntryUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Any updates force recreate of the resource
	return nil
}

func resourceZoneEntryDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*APIClient)

	// Construct the URL to delete the interface from the Zone
	req_url := fmt.Sprintf("https://%s/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/zone/entry[@name='%s']/network/layer3/member[text()='%s']",
		client.Host, url.QueryEscape(d.Get("template").(string)), url.QueryEscape(d.Get("vsys").(string)), url.QueryEscape(d.Get("name").(string)), url.QueryEscape(d.Get("interface").(string)))

	req, _ := http.NewRequest("GET", req_url, nil)
	apiKey, _ := getAPIKey(client.Host, client.Username, client.Password, client.SkipSSLVerification)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-PAN-KEY", apiKey)
	httpClient := buildHttpClient(client.SkipSSLVerification)
	resp, err := httpClient.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()
	// Read and check response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(err)
	}
	if resp.StatusCode != 200 {
		return diag.Errorf("Failed to remove interface from Zone: %s", string(body))
	}
	// Catch failures in the response
	resp_err := checkXMLResponse(body)
	if resp_err != nil {
		return diag.FromErr(resp_err)
	}
	// Set the ID back to empty as the interface has been deleted
	d.SetId("")
	// Return nothing as we only return the error if there was one
	return nil
}
