package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sensu-community/sensu-plugin-sdk/sensu"
	v2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-go/types"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	External           bool
	Namespace          string
	Kubeconfig         string
	LabelSelectors     string
	DisabledLabel      string
	MainHandler        string
	SensuNamespace     string
	Configuration      string
	HandlerKeyFilePath string
	ReservedNames      string
	APIBackendPass     string
	APIBackendUser     string
	APIBackendKey      string
	APIBackendHost     string
	APIBackendPort     int
	Secure             bool
	TrustedCAFile      string
	InsecureSkipVerify bool
	Protocol           string
}

// SecretWrapper struct
type SecretWrapper struct {
	Name            string            `json:"name"`
	Contacts        string            `json:"contacts"`
	MatchNamespaces map[string]string `json:"match_namespaces"`
	Keys            map[string]string `json:"keys"`
	Transform       string            `json:"transform"`
	Disabled        bool              `json:"disabled"`
}

// Auth represents the authentication info
type Auth struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// ConfigWrapper struct
type ConfigWrapper struct {
	Name           string          `json:"name"`
	PrefixName     string          `json:"prefix_name"`
	Handlers       []HandlerConfig `json:"handlers"`
	MutatorCommand string          `json:"mutator_command"`
	Mutator        bool            `json:"mutator"`
	MutatorAsset   []string        `json:"mutator_asset"`
	Timeout        uint32          `json:"timeout"`
}

// HandlerConfig struct
type HandlerConfig struct {
	KeyName string   `json:"key_name"`
	Command string   `json:"command"`
	Asset   []string `json:"asset"`
}

var (
	tlsConfig     tls.Config
	configuration ConfigWrapper
	reservedNames []string

	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "secret-to-handler",
			Short:    "Reads a K8S secret and publish a handler in sensu",
			Keyspace: "sensu.io/plugins/secret-to-handler/config",
		},
	}

	options = []*sensu.PluginConfigOption{
		{
			Path:      "namespace",
			Env:       "KUBERNETES_NAMESPACE",
			Argument:  "namespace",
			Shorthand: "N",
			Default:   "",
			Usage:     "Namespace to which to limit this check",
			Value:     &plugin.Namespace,
		},
		{
			Path:      "external",
			Env:       "",
			Argument:  "external",
			Shorthand: "e",
			Default:   false,
			Usage:     "Connect to cluster externally (using kubeconfig)",
			Value:     &plugin.External,
		},
		{
			Path:      "kubeconfig",
			Env:       "KUBERNETES_CONFIG",
			Argument:  "kubeconfig",
			Shorthand: "C",
			Default:   "",
			Usage:     "Path to the kubeconfig file (default $HOME/.kube/config)",
			Value:     &plugin.Kubeconfig,
		},
		{
			Path:      "label-selectors",
			Env:       "KUBERNETES_LABEL_SELECTORS",
			Argument:  "label-selectors",
			Shorthand: "l",
			Default:   "",
			Usage:     "Query for labelSelectors (e.g. release=stable,environment=qa)",
			Value:     &plugin.LabelSelectors,
		},
		{
			Path:      "disabled-label",
			Env:       "KUBERNETES_DISABLED_LABEL",
			Argument:  "disabled-label",
			Shorthand: "D",
			Default:   "",
			Usage:     "Query for disabled label (e.g. sync=disabled)",
			Value:     &plugin.DisabledLabel,
		},
		{
			Path:      "main-handler",
			Env:       "MAIN_HANDLER",
			Argument:  "main-handler",
			Shorthand: "m",
			Default:   "all-alerts",
			Usage:     "Main handler of type set to add all new handlers",
			Value:     &plugin.MainHandler,
		},
		{
			Path:      "handler-key-file-path",
			Env:       "HANDLER_KEY_PATH",
			Argument:  "handler-key-file-path",
			Shorthand: "f",
			Default:   "",
			Usage:     "Handler Key file path to be used instead paste key into handler command",
			Value:     &plugin.HandlerKeyFilePath,
		},
		{
			Path:      "config",
			Env:       "",
			Argument:  "config",
			Shorthand: "c",
			Default:   "",
			Usage:     "Json template for Sensu Check",
			Value:     &plugin.Configuration,
		},
		{
			Path:      "reserved-names",
			Env:       "",
			Argument:  "reserved-names",
			Shorthand: "R",
			Default:   "",
			Usage:     "Reserved Names already in use for Sensu that cannot be used anymore (list splited by comma , )",
			Value:     &plugin.ReservedNames,
		},
		{
			Path:      "sensu-namespace",
			Env:       "SENSU_NAMESPACE",
			Argument:  "sensu-namespace",
			Shorthand: "n",
			Default:   "",
			Usage:     "Namespace to which to limit this check",
			Value:     &plugin.SensuNamespace,
		},
		{
			Path:      "api-backend-user",
			Env:       "SENSU_API_USER",
			Argument:  "api-backend-user",
			Shorthand: "u",
			Default:   "admin",
			Usage:     "Sensu Go Backend API User",
			Value:     &plugin.APIBackendUser,
		},
		{
			Path:      "api-backend-pass",
			Env:       "SENSU_API_PASSWORD",
			Argument:  "api-backend-pass",
			Shorthand: "P",
			Default:   "P@ssw0rd!",
			Usage:     "Sensu Go Backend API Password",
			Value:     &plugin.APIBackendPass,
		},
		{
			Path:      "api-backend-key",
			Env:       "SENSU_API_KEY",
			Argument:  "api-backend-key",
			Shorthand: "k",
			Default:   "",
			Usage:     "Sensu Go Backend API Key",
			Value:     &plugin.APIBackendKey,
		},
		{
			Path:      "api-backend-host",
			Env:       "",
			Argument:  "api-backend-host",
			Shorthand: "B",
			Default:   "127.0.0.1",
			Usage:     "Sensu Go Backend API Host (e.g. 'sensu-backend.example.com')",
			Value:     &plugin.APIBackendHost,
		},
		{
			Path:      "api-backend-port",
			Env:       "",
			Argument:  "api-backend-port",
			Shorthand: "p",
			Default:   8080,
			Usage:     "Sensu Go Backend API Port (e.g. 4242)",
			Value:     &plugin.APIBackendPort,
		},
		{
			Path:      "secure",
			Env:       "",
			Argument:  "secure",
			Shorthand: "s",
			Default:   false,
			Usage:     "Use TLS connection to API",
			Value:     &plugin.Secure,
		},
		{
			Path:      "insecure-skip-verify",
			Env:       "",
			Argument:  "insecure-skip-verify",
			Shorthand: "i",
			Default:   false,
			Usage:     "skip TLS certificate verification (not recommended!)",
			Value:     &plugin.InsecureSkipVerify,
		},
		{
			Path:      "trusted-ca-file",
			Env:       "",
			Argument:  "trusted-ca-file",
			Shorthand: "t",
			Default:   "",
			Usage:     "TLS CA certificate bundle in PEM format",
			Value:     &plugin.TrustedCAFile,
		},
	}
)

func main() {
	check := sensu.NewGoCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *types.Event) (int, error) {
	if plugin.External {
		if len(plugin.Kubeconfig) == 0 {
			if home := homeDir(); home != "" {
				plugin.Kubeconfig = filepath.Join(home, ".kube", "config")
			}
		}
	}
	// For Sensu Backend Connections
	if plugin.Secure {
		plugin.Protocol = "https"
	} else {
		plugin.Protocol = "http"
	}
	if len(plugin.TrustedCAFile) > 0 {
		caCertPool, err := v2.LoadCACerts(plugin.TrustedCAFile)
		if err != nil {
			return sensu.CheckStateWarning, fmt.Errorf("Error loading specified CA file")
		}
		tlsConfig.RootCAs = caCertPool
	}
	tlsConfig.InsecureSkipVerify = plugin.InsecureSkipVerify

	// tlsConfig.BuildNameToCertificate()
	tlsConfig.CipherSuites = v2.DefaultCipherSuites

	if len(plugin.Configuration) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--config is required")
	}
	err := json.Unmarshal([]byte(plugin.Configuration), &configuration)
	if err != nil {
		return sensu.CheckStateWarning, err
	}
	if len(configuration.Handlers) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("in configuration you should provide at least one handler")
	}
	if len(configuration.Handlers) > 5 {
		return sensu.CheckStateWarning, fmt.Errorf("too many handler to be configured at same time")
	}
	if plugin.ReservedNames != "" {
		if strings.Contains(plugin.ReservedNames, ",") {
			reservedNames = strings.Split(plugin.ReservedNames, ",")
		} else {
			// if doesn't have comma, use this value
			reservedNames = []string{plugin.ReservedNames}
		}
	}
	// adding main handler into reserved names list
	reservedNames = append(reservedNames, plugin.MainHandler)

	return sensu.CheckStateOK, nil
}

func executeCheck(event *types.Event) (int, error) {
	var config *rest.Config
	var err error

	if plugin.External {
		config, err = clientcmd.BuildConfigFromFlags("", plugin.Kubeconfig)
		if err != nil {
			return sensu.CheckStateCritical, fmt.Errorf("Failed to get kubeconfig: %v", err)
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return sensu.CheckStateCritical, fmt.Errorf("Failed to get in InClusterConfig: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return sensu.CheckStateCritical, fmt.Errorf("Failed to get clientset: %v", err)
	}
	listOptions := metav1.ListOptions{}
	if len(plugin.LabelSelectors) > 0 {
		listOptions.LabelSelector = plugin.LabelSelectors
	}
	secrets, err := clientset.CoreV1().Secrets(plugin.Namespace).List(context.TODO(), listOptions)
	if err != nil {
		return sensu.CheckStateCritical, fmt.Errorf("Failed to get secrets: %v", err)
	}

	fmt.Printf("Number of kubernetes secrets found: %d \n", len(secrets.Items))
	var counterErrors int
	var errorsNames []string
	var secretsWrapper []SecretWrapper
	var notSyncedList []string
	for _, item := range secrets.Items {
		if plugin.DisabledLabel != "" {
			if checkDisabledLabels(item.Labels, plugin.DisabledLabel) {
				notSyncedList = append(notSyncedList, item.Name)
				continue
			}
		}
		var secret SecretWrapper
		for k, v := range item.Data {
			// each secret found: create a filter, mutator and handler ; update handler all-alerts set if needed
			// it doesnt create any asset, but uses this one sensu/sensu-go-has-contact-filter
			var counterLocalErrors int
			if k == "name" {
				secret.Name = string(v)
			}
			if k == "contacts" {
				secret.Contacts = string(v)
			}
			if k == "match_namespaces" {
				temp := make(map[string]string)
				err := yaml.Unmarshal(v, &temp)
				if err != nil {
					fmt.Println("fail in Unmarshal")
					counterLocalErrors++
				}
				secret.MatchNamespaces = temp
			}
			if k == "transform" {
				secret.Transform = string(v)
			}
			if k == "disabled" {
				secret.Disabled = false
				tmp := string(v)
				if strings.Contains(tmp, "True") || strings.Contains(tmp, "true") {
					secret.Disabled = true
				}
			}
			if k == "keys" {
				temp := make(map[string]string)
				err := yaml.Unmarshal(v, &temp)
				if err != nil {
					fmt.Println("fail in Unmarshal")
					counterLocalErrors++
				}
				secret.Keys = temp
			}
			if counterLocalErrors != 0 {
				counterErrors = counterLocalErrors
				errorsNames = append(errorsNames, item.Name)
			}
		}
		secretsWrapper = append(secretsWrapper, secret)
	}
	// if dont find any secret, just exit
	if len(secretsWrapper) == 0 {
		if len(notSyncedList) != 0 {
			fmt.Printf("Not synced secrets: %v ", notSyncedList)
		}
		return sensu.CheckStateOK, nil
	}

	var autherr error
	auth := Auth{}
	if len(plugin.APIBackendKey) == 0 {
		auth, autherr = authenticate()
		if autherr != nil {
			return sensu.CheckStateUnknown, autherr
		}
	}
	labels := map[string]string{
		plugin.Name: "owner",
	}
	var countErrors int
	// variables to collect outputs
	var errorsSensu, deletedNotFound, conflictSecretNames []string
	// list of handlers to add/remove to/from main handler
	var handlers, disabledHandlers []string
	// create all handlers, filters and mutators
	for _, secret := range secretsWrapper {
		// check if secret found has basic config: contacts and one key
		if secret.Contacts == "" || secret.Keys == nil {
			errorsSensu = append(errorsSensu, fmt.Sprintf("invalid secret %s", secret.Name))
			continue
		}
		if StringInSlice(secret.Name, reservedNames) {
			conflictSecretNames = append(conflictSecretNames, fmt.Sprintf("secret using reserved names %s %v", secret.Name, reservedNames))
			continue
		}
		// if Transform is empty, disable mutator
		validMutator := configuration.Mutator
		if secret.Transform == "" {
			validMutator = false
		}
		name := secret.Name
		if configuration.PrefixName != "" {
			name = fmt.Sprintf("%s-%s", configuration.PrefixName, secret.Name)
		}
		namespace := plugin.SensuNamespace
		contacts := secret.Contacts
		filter := generateFilter(name, namespace, contacts, labels)
		if !secret.Disabled {
			fmt.Printf("Creating filter %s\n", name)
			err := sensuRequest(auth, "filter", name, namespace, http.MethodPut, filter)
			if err != nil {
				countErrors++
				errorsSensu = append(errorsSensu, fmt.Sprintf("filter %s", secret.Name))
			}
		} else {
			fmt.Printf("Deleting disabled filter %s\n", name)
			err := sensuRequest(auth, "filter", name, namespace, http.MethodDelete, filter)
			if err != nil {
				deletedNotFound = append(deletedNotFound, fmt.Sprintf("Deleting filter %s", secret.Name))
			}
		}

		if validMutator {
			mutatorCommand := fmt.Sprintf("%s '%s'", configuration.MutatorCommand, secret.Transform)
			mutatorAssets := configuration.MutatorAsset
			mutator := generateMutator(name, namespace, mutatorCommand, mutatorAssets, labels)
			if !secret.Disabled {
				fmt.Printf("Creating mutator %s\n", name)
				err := sensuRequest(auth, "mutator", name, namespace, http.MethodPut, mutator)
				if err != nil {
					countErrors++
					errorsSensu = append(errorsSensu, fmt.Sprintf("mutator %s", secret.Name))
				}
			} else {
				fmt.Printf("Deleting disabled mutator %s\n", name)
				err := sensuRequest(auth, "mutator", name, namespace, http.MethodDelete, mutator)
				if err != nil {
					deletedNotFound = append(deletedNotFound, fmt.Sprintf("Deleting mutator %s", secret.Name))
				}
			}

		}
		var timeout uint32
		timeout = 10
		if configuration.Timeout != 0 {
			timeout = configuration.Timeout
		}
		for _, h := range configuration.Handlers {
			for k, v := range secret.Keys {
				if h.KeyName == k {
					handlerName := fmt.Sprintf("%s-%s", name, h.KeyName)
					handlerCommand := fmt.Sprintf("%s '%s'", h.Command, v)
					if plugin.HandlerKeyFilePath != "" {
						handlerCommand = fmt.Sprintf("%s $(cat %s/%s-%s)", h.Command, plugin.HandlerKeyFilePath, h.KeyName, name)
					}
					handlerAssets := h.Asset
					handler := generateHandler(handlerName, namespace, handlerCommand, name, handlerAssets, labels, validMutator, timeout)
					if !secret.Disabled {
						fmt.Printf("Creating handler %s\n", handlerName)
						err := sensuRequest(auth, "handler", handlerName, namespace, http.MethodPut, handler)
						if err != nil {
							countErrors++
							errorsSensu = append(errorsSensu, fmt.Sprintf("handler %s %s", h.KeyName, secret.Name))
						}
						handlers = append(handlers, handlerName)
					} else {
						fmt.Printf("Deleting disabled handler %s\n", handlerName)
						err := sensuRequest(auth, "handler", handlerName, namespace, http.MethodDelete, handler)
						if err != nil {
							deletedNotFound = append(deletedNotFound, fmt.Sprintf("Deleting handler %s %s", h.KeyName, secret.Name))
						}
						disabledHandlers = append(disabledHandlers, handlerName)
					}

				}
			}
		}
	}
	mainHandler, err := getHandler(auth, plugin.MainHandler, plugin.SensuNamespace)
	if err != nil {
		return sensu.CheckStateWarning, fmt.Errorf("cannot get main handler %s %v", plugin.MainHandler, err)
	}
	if mainHandler.Name == "" {
		fmt.Println("Main Handler not found, creating a empty one")
		mainHandler = &v2.Handler{}
		mainHandler.Name = plugin.MainHandler
		mainHandler.Namespace = plugin.SensuNamespace
		mainHandler.Labels = labels
		mainHandler.Type = "set"
	}
	// generate a handler's names list to add to main handler
	var negativeHandlerList []string
	checkDisabledList := false
	if len(mainHandler.Handlers) != 0 {
		for _, h := range handlers {
			if !StringInSlice(h, mainHandler.Handlers) {
				negativeHandlerList = append(negativeHandlerList, h)
			}
		}
		checkDisabledList = true
	} else {
		negativeHandlerList = handlers
	}
	mainHandlerList := mainHandler.Handlers
	// removing disabled secrets
	if len(disabledHandlers) != 0 && checkDisabledList {
		fmt.Println("Removing disabled handlers from Main Handler")
		tmpMainHandlerList := []string{}
		for _, h := range mainHandlerList {
			if !StringInSlice(h, disabledHandlers) {
				tmpMainHandlerList = append(tmpMainHandlerList, h)
			}
		}
		mainHandlerList = tmpMainHandlerList
	}

	if len(negativeHandlerList) != 0 {
		mainHandler.Handlers = append(mainHandlerList, negativeHandlerList...)
		encoded, _ := json.Marshal(mainHandler)
		update := bytes.NewBuffer(encoded)
		err := sensuRequest(auth, "handler", plugin.MainHandler, plugin.SensuNamespace, http.MethodPut, update)
		if err != nil {
			return sensu.CheckStateWarning, fmt.Errorf("cannot update main handler %s %v", plugin.MainHandler, err)
		}
	}

	// return warning if cannot handle with some secrets
	if counterErrors != 0 {
		return sensu.CheckStateWarning, fmt.Errorf("cannot parse these secrets: %v", errorsNames)
	}

	if countErrors != 0 {
		return sensu.CheckStateWarning, fmt.Errorf("cannot parse create these sensu configurations: %v", errorsSensu)
	}

	if len(deletedNotFound) != 0 {
		fmt.Printf("Resouces to delete not found: %v \n", deletedNotFound)
	}

	if len(conflictSecretNames) != 0 {
		fmt.Printf("Conflicted resouces not synced: %v \n", conflictSecretNames)
	}

	if len(notSyncedList) != 0 {
		fmt.Printf("Not synced secrets: %v \n", notSyncedList)
	}
	return sensu.CheckStateOK, nil
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

// authenticate funcion to work with api-backend-* flags
func authenticate() (Auth, error) {
	var auth Auth
	client := http.DefaultClient
	client.Transport = http.DefaultTransport

	if plugin.Secure {
		client.Transport.(*http.Transport).TLSClientConfig = &tlsConfig
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s://%s:%d/auth", plugin.Protocol, plugin.APIBackendHost, plugin.APIBackendPort),
		nil,
	)
	if err != nil {
		return auth, fmt.Errorf("error generating auth request: %v", err)
	}

	req.SetBasicAuth(plugin.APIBackendUser, plugin.APIBackendPass)

	resp, err := client.Do(req)
	if err != nil {
		return auth, fmt.Errorf("error executing auth request: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return auth, fmt.Errorf("error reading auth response: %v", err)
	}

	if strings.HasPrefix(string(body), "Unauthorized") {
		return auth, fmt.Errorf("authorization failed for user %s", plugin.APIBackendUser)
	}

	err = json.NewDecoder(bytes.NewReader(body)).Decode(&auth)

	if err != nil {
		trim := 64
		return auth, fmt.Errorf("error decoding auth response: %v\nFirst %d bytes of response: %s", err, trim, trimBody(body, trim))
	}

	return auth, err
}

// used to clean errors output
func trimBody(body []byte, maxlen int) string {
	if len(string(body)) < maxlen {
		maxlen = len(string(body))
	}

	return string(body)[0:maxlen]
}

// get events from sensu-backend-api
func getHandler(auth Auth, name, namespace string) (*types.Handler, error) {
	client := http.DefaultClient
	client.Transport = http.DefaultTransport

	url := fmt.Sprintf("%s://%s:%d/api/core/v2/namespaces/%s/handlers/%s", plugin.Protocol, plugin.APIBackendHost, plugin.APIBackendPort, namespace, name)
	handlers := &types.Handler{}

	if plugin.Secure {
		client.Transport.(*http.Transport).TLSClientConfig = &tlsConfig
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return handlers, fmt.Errorf("error creating GET request for %s: %v", url, err)
	}

	if len(plugin.APIBackendKey) == 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.AccessToken))
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("Key %s", plugin.APIBackendKey))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return handlers, fmt.Errorf("error executing GET request for %s: %v", url, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return handlers, fmt.Errorf("error reading response body during getHandlers: %v", err)
	}

	err = json.Unmarshal(body, &handlers)
	if err != nil {
		trim := 64
		return handlers, fmt.Errorf("error unmarshalling response during getHandlers: %v\nFirst %d bytes of response: %s", err, trim, trimBody(body, trim))
	}

	return handlers, err
}

func putURLManager(sensu, name, namespace string) string {
	switch sensu {
	case "handler":
		return fmt.Sprintf("%s://%s:%d/api/core/v2/namespaces/%s/handlers/%s", plugin.Protocol, plugin.APIBackendHost, plugin.APIBackendPort, namespace, name)
	case "filter":
		return fmt.Sprintf("%s://%s:%d/api/core/v2/namespaces/%s/filters/%s", plugin.Protocol, plugin.APIBackendHost, plugin.APIBackendPort, namespace, name)
	case "mutator":
		return fmt.Sprintf("%s://%s:%d/api/core/v2/namespaces/%s/mutators/%s", plugin.Protocol, plugin.APIBackendHost, plugin.APIBackendPort, namespace, name)
	}
	return ""
}

// put or delete handler to sensu-backend-api
func sensuRequest(auth Auth, sensu, name, namespace, method string, body io.Reader) error {
	client := http.DefaultClient
	client.Transport = http.DefaultTransport
	url := putURLManager(sensu, name, namespace)
	if plugin.Secure {
		client.Transport.(*http.Transport).TLSClientConfig = &tlsConfig
	}
	// s, err := json.MarshalIndent(check, "", "\t")
	// fmt.Println(string(s), url)
	// encoded, _ := json.Marshal(check)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return fmt.Errorf("Failed to %s event to %s failed: %v", method, url, err)
	}
	if len(plugin.APIBackendKey) == 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.AccessToken))
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("Key %s", plugin.APIBackendKey))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error executing %s request for %s: %v", method, url, err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%s of event to %s failed with status %v ", method, url, resp.Status)
	}

	defer resp.Body.Close()

	return err
}

func generateHandler(name, namespace, command, filter string, assets []string, labels map[string]string, mutator bool, timeout uint32) io.Reader {
	handler := &types.Handler{}
	handler.Name = name
	handler.Namespace = namespace
	handler.Labels = labels
	handler.Command = command
	handler.Timeout = timeout
	handler.Type = "pipe"
	handler.RuntimeAssets = assets
	filters := []string{"is_incident", "not_silenced", filter}
	handler.Filters = filters
	if mutator {
		handler.Mutator = filter
	}

	encoded, _ := json.Marshal(handler)
	return bytes.NewBuffer(encoded)
}

func generateFilter(name, namespace, contact string, labels map[string]string) io.Reader {
	filter := &types.EventFilter{}
	filter.Name = name
	filter.Namespace = namespace
	filter.Labels = labels
	filter.Action = "allow"
	filter.RuntimeAssets = []string{"sensu-go-has-contact-filter"}
	expression := fmt.Sprintf("has_contact(event, \"%s\")", contact)
	filter.Expressions = []string{expression}
	encoded, _ := json.Marshal(filter)
	return bytes.NewBuffer(encoded)
}

func generateMutator(name, namespace, command string, asset []string, labels map[string]string) io.Reader {
	mutator := &types.Mutator{}
	mutator.Name = name
	mutator.Namespace = namespace
	mutator.Labels = labels
	mutator.Command = command
	mutator.RuntimeAssets = asset

	encoded, _ := json.Marshal(mutator)
	return bytes.NewBuffer(encoded)
}

//StringInSlice checks if a slice contains a specific string
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func checkDisabledLabels(labels map[string]string, label string) bool {
	var key, value string
	if strings.Contains(label, "=") {
		splited := strings.Split(label, "=")
		key = splited[0]
		value = splited[1]
	}
	for k, v := range labels {
		if k == key && v == value {
			return true
		}
	}
	return false
}
