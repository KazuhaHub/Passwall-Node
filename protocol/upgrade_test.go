package protocol

import "testing"

func TestEffectiveFullReportPeriodMatchesPollingSchedule(t *testing.T) {
	tests := []struct {
		name     string
		full     int
		poll     int
		expected int
	}{
		{name: "defaults", full: 0, poll: 0, expected: DefaultNextPollSeconds},
		{name: "every poll", full: 0, poll: 7, expected: 7},
		{name: "exact multiple", full: 60, poll: 30, expected: 60},
		{name: "between polls", full: 45, poll: 30, expected: 60},
		{name: "just after poll", full: 31, poll: 30, expected: 60},
		{name: "shorter than poll", full: 1, poll: 30, expected: 30},
		{name: "third poll", full: 61, poll: 30, expected: 90},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := EffectiveFullReportPeriod(test.full, test.poll); got != test.expected {
				t.Fatalf("EffectiveFullReportPeriod(%d, %d) = %d, want %d", test.full, test.poll, got, test.expected)
			}
		})
	}
}

func TestDecodeAgentUpgradeArgsRequiresExactObject(t *testing.T) {
	valid := []byte(`{"version":"v1.2.3","expected_version":"v1.2.2"}`)
	args, err := DecodeAgentUpgradeArgs(valid)
	if err != nil {
		t.Fatal(err)
	}
	if args.Version != "v1.2.3" || args.ExpectedVersion != "v1.2.2" {
		t.Fatalf("decoded args = %#v", args)
	}
	for _, invalid := range []string{
		`null`,
		`[]`,
		`{"version":"v1.2.3"}`,
		`{"version":"v1.2.3","expected_version":"v1.2.2","url":"https://evil.test"}`,
		`{"version":"v1.2.3","version":"v1.2.4","expected_version":"v1.2.2"}`,
		`{"version":3,"expected_version":"v1.2.2"}`,
		`{"version":"v1.2.3","expected_version":"v1.2.2"} {}`,
	} {
		if _, err := DecodeAgentUpgradeArgs([]byte(invalid)); err == nil {
			t.Errorf("accepted %s", invalid)
		}
	}
}

func TestDecodeAgentUpgradeResultRequiresExactObject(t *testing.T) {
	valid := []byte(`{"version":"v1.2.3","previous_version":"v1.2.2","binary_sha256":"abc","restarted":true}`)
	result, err := DecodeAgentUpgradeResult(valid)
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != "v1.2.3" || result.PreviousVersion != "v1.2.2" || result.BinarySHA256 != "abc" || !result.Restarted {
		t.Fatalf("decoded result = %#v", result)
	}
	for _, invalid := range []string{
		`{"version":"v1.2.3","previous_version":"v1.2.2","binary_sha256":"abc"}`,
		`{"version":"v1.2.3","previous_version":"v1.2.2","binary_sha256":"abc","restarted":true,"pid":1}`,
		`{"version":"v1.2.3","previous_version":"v1.2.2","binary_sha256":"abc","restarted":1}`,
	} {
		if _, err := DecodeAgentUpgradeResult([]byte(invalid)); err == nil {
			t.Errorf("accepted %s", invalid)
		}
	}
}
