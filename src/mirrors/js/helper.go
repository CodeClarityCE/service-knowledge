package js

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/CodeClarityCE/service-knowledge/src/utilities/types"
)

type NpmChanges struct {
	Last_seq string      `json:"last_seq"`
	Results  []NpmResult `json:"results"`
}

type NpmResult struct {
	Changes []struct {
		Rev string `json:"rev"`
	} `json:"changes"`
	ID      string `json:"id"`
	Seq     string `json:"seq"`
	Deleted bool   `json:"deleted"`
}

// download is a function that downloads an npm package from the npm registry.
// It takes a package name as input and returns the downloaded package information
// as a types.Npm struct and an error if any.
func download(pack string) (types.Npm, error) {
	// Read environment variable NPM_URL
	npmURL := os.Getenv("NPM_URL")
	if npmURL == "" {
		log.Println("NPM_URL environment variable is not set")
		npmURL = "http://localhost:5984/npm/"
	}
	couchLogin := os.Getenv("COUCH_LOGIN")
	// if couchLogin == "" {
	// 	log.Println("COUCH_LOGIN environment variable is not set")
	// }
	couchPassword := os.Getenv("COUCH_PASSWORD")
	// if couchPassword == "" {
	// 	log.Println("COUCH_PASSWORD environment variable is not set")
	// }

	pack = url.QueryEscape(pack)
	url := fmt.Sprintf("%s%s", npmURL, pack)

	// Concatenate int in url
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(err)
		return types.Npm{}, err
	}

	// Add Authorization header
	if couchLogin != "" && couchPassword != "" {
		user := couchLogin
		password := couchPassword
		auth := user + ":" + password
		encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
		req.Header.Set("Authorization", "Basic "+encodedAuth)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return types.Npm{}, err
	}

	defer resp.Body.Close()

	// resp, err := http.Get("https://registry.npmjs.com/" + pack)

	if resp.StatusCode != 200 {
		if resp.StatusCode == 404 {
			return types.Npm{}, fmt.Errorf("package not found : %s (%s)", pack, resp.Status)
		} else if resp.StatusCode == 429 {
			time.Sleep(60 * time.Second)
			log.Println("Rate limited, waiting 60 seconds")
			return download(pack)
		} else {
			return types.Npm{}, fmt.Errorf("can't fetch package : %s (%s)", pack, resp.Status)
		}
	}

	var result types.Npm
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Can't read response body", err)
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Println("Can't unmarshal response body", err)
		return types.Npm{}, err
	}

	return result, nil
}
