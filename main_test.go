package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringInSlice(t *testing.T) {
	testSlice := []string{"foo", "bar", "test"}
	testString := "test"
	testResult := StringInSlice(testString, testSlice)
	assert.True(t, testResult)

	testSlice1 := []string{"foo", "bar", "testa"}
	testString1 := "testb"
	testResult1 := StringInSlice(testString1, testSlice1)
	assert.False(t, testResult1)
}
