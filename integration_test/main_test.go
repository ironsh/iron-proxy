package integration_test

import (
	"flag"
	"fmt"
	"os"
	"testing"
)

var integration = flag.Bool("integration", false, "run integration tests")

func TestMain(m *testing.M) {
	flag.Parse()
	if !*integration {
		fmt.Println("skipping integration tests (pass -integration to run)")
		return
	}
	os.Exit(m.Run())
}
