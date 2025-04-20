package pan_sdwan

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// XML Response Structs
type KeyGenResponse struct {
	XMLName xml.Name `xml:"response"`
	Text    string   `xml:",chardata"`
	Status  string   `xml:"status,attr"`
	Result  struct {
		Text string `xml:",chardata"`
		Key  string `xml:"key"`
	} `xml:"result"`
}

type sdwanInterface struct {
	XMLName xml.Name `xml:"response"`
	Text    string   `xml:",chardata"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Result  struct {
		Text       string `xml:",chardata"`
		TotalCount string `xml:"total-count,attr"`
		Count      string `xml:"count,attr"`
		Entry      struct {
			Text      string `xml:",chardata"`
			Name      string `xml:"name,attr"`
			Protocol  string `xml:"protocol"`
			Comment   string `xml:"comment"`
			Interface struct {
				Text   string   `xml:",chardata"`
				Member []string `xml:"member"`
			} `xml:"interface"`
		} `xml:"entry"`
	} `xml:"result"`
}

type XMLAPIResponse struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Msg     struct {
		Lines []string `xml:"line"`
	} `xml:"msg"`
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

func getAPIKey(deviceIP, username, password string, skip_verify bool) (string, error) {
	// Create a custom HTTP client to allow insecure SSL connections if required by the provider
	client := buildHttpClient(skip_verify)

	// Construct the URL for the KeyGen API
	keyGenURL := fmt.Sprintf("https://%s/api/?type=keygen&user=%s&password=%s", deviceIP, username, password)

	// Send the request to the PAN Device
	resp, err := client.Get(keyGenURL)
	if err != nil {
		return "", fmt.Errorf("error making the request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body back from PAN
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading the response body: %v", err)
	}

	// Parse the XML response to get the API Key
	var keyGenResp KeyGenResponse
	err = xml.Unmarshal(body, &keyGenResp)
	if err != nil {
		return "", fmt.Errorf("error unmarshalling the XML response: %v", err)
	}

	// Check if the API key was retrieved
	if keyGenResp.Result.Key == "" {
		return "", fmt.Errorf("API key not found in the response")
	}
	// Return the API key
	return keyGenResp.Result.Key, nil
}

func resourceSDWANInterface() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceSDWANInterfaceCreate,
		ReadContext:   resourceSDWANInterfaceRead,
		UpdateContext: resourceSDWANInterfaceUpdate,
		DeleteContext: resourceSDWANInterfaceDelete,
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
			"members": {
				Type:     schema.TypeList,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				ForceNew: true,
			},
			"protocol": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "ipv4",
			},
			"comment": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"vsys": {
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func addInterfaceToVsys(apiKey, deviceIP, username, password, interfaceToAdd, template, vsys string, skip_verify bool) diag.Diagnostics {
	// Create a custom HTTP client to allow insecure SSL connections if required by the provider
	client := buildHttpClient(skip_verify)

	// Construct the URL to import interface into vsys
	vsysURL := fmt.Sprintf("https://%s/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/import/network/interface&element=<member>%s</member>", deviceIP, template, vsys, interfaceToAdd)

	req, _ := http.NewRequest("GET", vsysURL, nil)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-PAN-KEY", apiKey)

	resp, err := client.Do(req)
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
		return diag.Errorf("Failed to remove interface from virtual-router: %s", string(body))
	}
	// Catch failures in the response
	resp_err := checkXMLResponse(body)
	if resp_err != nil {
		return diag.FromErr(resp_err)
	}
	// Return nothing as we only return the error if there was one
	return nil
}

func removeInterfaceFromVsys(apiKey, deviceIP, username, password, interfaceToRemove, template, vsys string, skip_verify bool) diag.Diagnostics {
	// Create a custom HTTP client to allow insecure SSL connections if required by the provider
	client := buildHttpClient(skip_verify)

	// Construct the URL to remove interface from vsys
	vsysURL := fmt.Sprintf("https://%s/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/import/network/interface/member[text()='%s']", deviceIP, template, vsys, interfaceToRemove)
	req, _ := http.NewRequest("GET", vsysURL, nil)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-PAN-KEY", apiKey)

	resp, err := client.Do(req)
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
		return diag.Errorf("Failed to remove interface from virtual-router: %s", string(body))
	}
	// Catch failures in the response
	resp_err := checkXMLResponse(body)
	if resp_err != nil {
		return diag.FromErr(resp_err)
	}
	// Return nothing as we only return the error if there was one
	return nil
}

func removeInterfaceFromVr(apiKey, deviceIP, username, password, interfaceToRemove, template, vr string, skip_verify bool) diag.Diagnostics {
	// Create a custom HTTP client to allow insecure SSL connections if required by the provider
	client := buildHttpClient(skip_verify)

	// Construct the URL to remove interface from virtual router
	vsysURL := fmt.Sprintf("https://%s/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='%s']/interface/member[text()='%s']", deviceIP, template, vr, interfaceToRemove)
	req, _ := http.NewRequest("GET", vsysURL, nil)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-PAN-KEY", apiKey)

	resp, err := client.Do(req)
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
		return diag.Errorf("Failed to remove interface from virtual-router: %s", string(body))
	}
	// Catch failures in the response
	resp_err := checkXMLResponse(body)
	if resp_err != nil {
		return diag.FromErr(resp_err)
	}
	// Return nothing as we only return the error if there was one
	return nil
}

func removeInterfaceFromZone(apiKey, deviceIP, username, password, interfaceToRemove, template, vsys, zone string, skip_verify bool) diag.Diagnostics {
	// Create a custom HTTP client to allow insecure SSL connections if required by the provider
	client := buildHttpClient(skip_verify)

	// Construct the URL to remove interface from zone
	vsysURL := fmt.Sprintf("https://%s/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/zone/entry[@name='%s']/network/layer3/member[text()='%s']", deviceIP, template, vsys, zone, interfaceToRemove)
	req, _ := http.NewRequest("GET", vsysURL, nil)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-PAN-KEY", apiKey)

	resp, err := client.Do(req)
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
		return diag.Errorf("Failed to remove interface from virtual-router: %s", string(body))
	}
	// Catch failures in the response
	resp_err := checkXMLResponse(body)
	if resp_err != nil {
		return diag.FromErr(resp_err)
	}
	// Return nothing as we only return the error if there was one
	return nil
}

func buildSdwanInterfaceElement(protocol, comment string, interfaces []interface{}) string {
	// Build the XML element string for the sdwan interface
	var sb strings.Builder
	members := make([]string, len(interfaces))
	for i, v := range interfaces {
		members[i] = v.(string)
	}
	sb.WriteString(fmt.Sprintf("<protocol>%s</protocol>", protocol))
	sb.WriteString(fmt.Sprintf("<comment>%s</comment>", comment))
	sb.WriteString("<interface>")

	for _, intf := range members {
		sb.WriteString(fmt.Sprintf("<member>%s</member>", intf))
	}
	sb.WriteString("</interface>")
	return sb.String()
}

func resourceSDWANInterfaceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*APIClient)

	// Create XML Element string from resourc inputs
	elementString := buildSdwanInterfaceElement("ipv4", d.Get("comment").(string), d.Get("members").([]interface{}))
	// Construct the URL to create the sdwan interface
	url := fmt.Sprintf("https://%s/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/network/interface/sdwan/units/entry[@name='%s']&element=%s",
		client.Host, d.Get("template").(string), d.Get("name").(string), elementString)

	req, _ := http.NewRequest("GET", url, nil)
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
		return diag.Errorf("Failed to remove interface from virtual-router: %s", string(body))
	}
	// Catch failures in the response
	resp_err := checkXMLResponse(body)
	if resp_err != nil {
		return diag.FromErr(resp_err)
	}
	// Add the sdwan interface to the required vsys as per the resource input
	vsys_add_err := addInterfaceToVsys(apiKey, client.Host, client.Username, client.Password, d.Get("name").(string), d.Get("template").(string), d.Get("vsys").(string), client.SkipSSLVerification)
	if vsys_add_err != nil {
		return diag.Errorf("addInterfaceToVsys error: %s, %s", vsys_add_err[0].Summary, vsys_add_err[0].Detail)
	}
	// Set the ID back to terraform as the name of the interface
	d.SetId(d.Get("name").(string))
	// Return nothing as we only return the error if there was one
	return nil
}

func resourceSDWANInterfaceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*APIClient)
	// Construct the URL to get the sdwan interface
	url := fmt.Sprintf("https://%s/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/network/interface/sdwan/units/entry[@name='%s']",
		client.Host, d.Get("template").(string), d.Get("name").(string))

	req, _ := http.NewRequest("GET", url, nil)
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
	var sdwan_xml_resp sdwanInterface
	if err := xml.Unmarshal(body, &sdwan_xml_resp); err != nil {
		panic(err)
	}
	// Catch failures in the response
	if resp.StatusCode != 200 {
		return diag.Errorf("Error creating sdwan interface: %s", string(body))
	}
	if sdwan_xml_resp.Status == "error" {
		return diag.Errorf("Error getting sdwan interface: %s", string(body))
	}
	// Check if the interface exists
	if sdwan_xml_resp.Code == "7" {
		// This means the interface does not exist set the ID to empty and return
		d.SetId("")
		return nil
	}
	// Set the resource data back to terraform
	d.Set("template", d.Get("template").(string))
	d.Set("name", sdwan_xml_resp.Result.Entry.Name)
	d.Set("members", sdwan_xml_resp.Result.Entry.Interface.Member)
	d.Set("protocol", sdwan_xml_resp.Result.Entry.Protocol)
	d.Set("comment", sdwan_xml_resp.Result.Entry.Comment)
	d.Set("vsys", d.Get("vsys").(string))
	// Return nothing as we only return the error if there was one
	return nil
}

func resourceSDWANInterfaceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*APIClient)

	// Construct the URL to set the sdwan interface parameters
	url := fmt.Sprintf("https://%s/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/network/interface/sdwan/units/entry[@name='%s']&element=<protocol>ipv4</protocol><comment>%s</comment>",
		client.Host, d.Get("template").(string), d.Get("name").(string), d.Get("comment").(string))

	req, _ := http.NewRequest("GET", url, nil)
	apiKey, _ := getAPIKey(client.Host, client.Username, client.Password, client.SkipSSLVerification)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-PAN-KEY", apiKey)
	httpClient := buildHttpClient(client.SkipSSLVerification)

	resp, err := httpClient.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()
	// Catch failures in the response
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return diag.Errorf("API error creating sdwan interface: %s", string(body))
	} else {
		// Check to see if the vsys has changed on the resource
		// If it has changed we need to remove the interface from the old vsys and add it to the new one
		if d.HasChange("vsys") {
			vsys_before, vsys_after := d.GetChange("vsys")
			fmt.Println("Before:", vsys_before)
			fmt.Println("After:", vsys_after)
			// Remove the interface from the old vsys
			if vsys_before.(string) != "" {
				sdwan_vsys_rm_err := removeInterfaceFromVsys(apiKey, client.Host, client.Username, client.Password, d.Get("name").(string), d.Get("template").(string), vsys_before.(string), client.SkipSSLVerification)
				if sdwan_vsys_rm_err != nil {
					return diag.Errorf("SDWAN Update, Vsys remove error: %s, %s", sdwan_vsys_rm_err[0].Summary, sdwan_vsys_rm_err[0].Detail)
				}
			}
			// Add the interface to the new vsys
			sdwan_vsys_add_err := addInterfaceToVsys(apiKey, client.Host, client.Username, client.Password, d.Get("name").(string), d.Get("template").(string), vsys_after.(string), client.SkipSSLVerification)
			if sdwan_vsys_add_err != nil {
				return diag.Errorf("SDWAN Update, Vsys add error: %s, %s", sdwan_vsys_add_err[0].Summary, sdwan_vsys_add_err[0].Detail)

			}
		}
	}
	// Return nothing as we only return the error if there was one
	return nil
}

func resourceSDWANInterfaceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*APIClient)

	// Construct the URL to delete the sdwan interface - this is likely to fail if the interface is still referenced elsewhere
	url := fmt.Sprintf("https://%s/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/network/interface/sdwan/units/entry[@name='%s']",
		client.Host, d.Get("template").(string), d.Get("name").(string))

	req, _ := http.NewRequest("GET", url, nil)
	apiKey, _ := getAPIKey(client.Host, client.Username, client.Password, client.SkipSSLVerification)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-PAN-KEY", apiKey)
	httpClient := buildHttpClient(client.SkipSSLVerification)

	resp, err := httpClient.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, _ := io.ReadAll(resp.Body)
	var xml_resp XMLAPIResponse
	if err := xml.Unmarshal(body, &xml_resp); err != nil {
		panic(err)
	}
	// Catch failures in the response - which are expected if the interface is still referenced elsewhere
	if resp.StatusCode != 200 {
		return diag.Errorf("API error creating sdwanz interface: %s", string(body))
	}
	dependency_err := false
	if xml_resp.Status == "error" {
		// Likely the interface is still referenced elsewhere
		for _, line := range xml_resp.Msg.Lines {
			if strings.Contains(line, "cannot be deleted because of references from") {
				dependency_err = true
				fmt.Println("Found dependency error:", line)
			}
		}
		if dependency_err {
			// Parse the err to find the dependencies
			var virtualRouter, vsys, zone string
			for _, line := range xml_resp.Msg.Lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "virtual-router") {
					parts := strings.Split(line, "->")
					for i, part := range parts {
						if strings.TrimSpace(part) == "virtual-router" && i+1 < len(parts) {
							virtualRouter = strings.TrimSpace(parts[i+1])
						}
					}
				}
				if strings.Contains(line, "vsys") {
					parts := strings.Split(line, "->")
					for i, part := range parts {
						if strings.TrimSpace(part) == "vsys" && i+1 < len(parts) {
							vsys = strings.TrimSpace(parts[i+1])
						}
						if strings.TrimSpace(part) == "zone" && i+1 < len(parts) {
							zone = strings.TrimSpace(parts[i+1])
						}
					}
				}
			}
			// Remove the interface from its Virtual Router if its associated
			if virtualRouter != "" {
				vr_err := removeInterfaceFromVr(apiKey, client.Host, client.Username, client.Password, d.Get("name").(string), d.Get("template").(string), virtualRouter, client.SkipSSLVerification)
				if vr_err != nil {
					return diag.Errorf("SDWAN Delete, VR remove error: %s, %s", vr_err[0].Summary, vr_err[0].Detail)
				}
			}
			// Remove the interface from its Zone if its associated
			if zone != "" {
				zone_err := removeInterfaceFromZone(apiKey, client.Host, client.Username, client.Password, d.Get("name").(string), d.Get("template").(string), vsys, zone, client.SkipSSLVerification)
				if zone_err != nil {
					return diag.Errorf("SDWAN Delete, zone remove error: %s, %s", zone_err[0].Summary, zone_err[0].Detail)

				}
			}
			// Remove the interface from its Vsys if its associated

			if vsys != "" {
				vsys_err := removeInterfaceFromVsys(apiKey, client.Host, client.Username, client.Password, d.Get("name").(string), d.Get("template").(string), vsys, client.SkipSSLVerification)
				if vsys_err != nil {
					return diag.Errorf("SDWAN Delete, vsys remove error: %s, %s", vsys_err[0].Summary, vsys_err[0].Detail)
				}
			}
			// Construct the URL to delete the sdwan interface - now dependencies should be removed and this should work
			url := fmt.Sprintf("https://%s/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/config/devices/entry[@name='localhost.localdomain']/network/interface/sdwan/units/entry[@name='%s']",
				client.Host, d.Get("template").(string), d.Get("name").(string))

			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("Content-Type", "application/xml")
			req.Header.Set("X-PAN-KEY", apiKey)
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: client.SkipSSLVerification},
			}
			clientinsecure := &http.Client{
				Transport: tr,
				Timeout:   30 * time.Second, // Set a timeout for the request
			}

			resp, err := clientinsecure.Do(req)
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
				return diag.Errorf("Failed to remove interface from virtual-router: %s", string(body))
			}
			// Catch failures in the response
			resp_err := checkXMLResponse(body)
			if resp_err != nil {
				return diag.FromErr(resp_err)
			}
		}
	}
	// Set the ID back to empty as the interface has been deleted
	d.SetId("")
	// Return nothing as we only return the error if there was one
	return nil
}
