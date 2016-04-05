// Copyright © 2016 Joseph Wright <rjosephwright@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	bv "github.com/cloudboss/bossvault/lib"
	"github.com/spf13/cobra"
)

var (
	encNamespace string
	encArtifact  string
	encContent   string
	encBucket    string

	encryptCmd = &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt bytes and store the data in S3.",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := bv.NewBossVaultClient()
			err := client.EncryptAndStore(encBucket, encArtifact, encContent)
			if err != nil {
				return err
			}
			return nil
		},
	}
)

func init() {
	RootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringVarP(&encNamespace, "namespace", "n", "", "Namespace of artifacts")
	encryptCmd.Flags().StringVarP(&encArtifact, "artifact", "a", "", "Name of artifact to be encrypted")
	encryptCmd.Flags().StringVarP(&encBucket, "bucket", "b", "", "Name of bucket in which to store artifact")
	encryptCmd.Flags().StringVarP(&encContent, "content", "c", "", "Path to file containing content to be encrypted")
}
