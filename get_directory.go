package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func getDirectory(client http.Client, dir string) (*acmeEndpoints, error) {
	if dir == "" {
		return nil, errors.New("Directory URL not set")
	}

	req, err := http.NewRequest("GET", dir, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Directory request returned error %s", resp.Status)
	}

	var endpoints *acmeEndpoints
	if err := json.NewDecoder(resp.Body).Decode(endpoints); err != nil {
		return nil, err
	}

	return endpoints, nil
}
