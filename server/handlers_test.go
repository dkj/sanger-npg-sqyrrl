/*
 * Copyright (C) 2024. Genome Research Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package server_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"path/filepath"
	"time"

	"github.com/cyverse/go-irodsclient/irods/connection"
	"github.com/cyverse/go-irodsclient/irods/fs"
	"github.com/cyverse/go-irodsclient/irods/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sqyrrl/server"
)

var _ = Describe("iRODS Get Handler", func() {
	var testZone, rootColl, workColl string
	var testFile, localPath, remotePath string

	var testConfig server.Config
	var testServer *server.SqyrrlServer

	BeforeEach(func(ctx SpecContext) {
		// Put a test file into iRODS
		testZone = "testZone"
		rootColl = fmt.Sprintf("/%s/home/irods", testZone)
		workColl = TmpRodsPath(rootColl, "iRODSGetHandler")

		testConfig = server.Config{
			Host:          "localhost",
			Port:          "9999",
			EnableOIDC:    false,
			CertFilePath:  "./testdata/config/localhost.crt",
			KeyFilePath:   "./testdata/config/localhost.key",
			IndexInterval: time.Hour * 1,
		}

		var err error
		err = server.Configure(suiteLogger, &testConfig)
		Expect(err).NotTo(HaveOccurred())

		testServer, err = server.NewSqyrrlServer(suiteLogger, &testConfig)
		Expect(err).NotTo(HaveOccurred())

		err = testServer.StartBackground()
		Expect(err).NotTo(HaveOccurred())

		err = irodsFS.MakeDir(workColl, true)
		Expect(err).NotTo(HaveOccurred())

		testFile = "test.txt"
		localPath = filepath.Join("testdata", testFile)
		remotePath = path.Join(workColl, testFile)

		err = irodsFS.UploadFile(localPath, remotePath, "", false, nil)
		Expect(err).NotTo(HaveOccurred())
	}, NodeTimeout(time.Second*5))

	AfterEach(func() {
		testServer.Stop()
		// Remove the test file from iRODS
		err := irodsFS.RemoveDir(workColl, true, true)
		Expect(err).NotTo(HaveOccurred())
	})

	When("a non-existent path is given", func() {
		var r *http.Request
		var handler http.Handler
		var err error

		BeforeEach(func(ctx SpecContext) {
			handler, err = testServer.GetHandler(server.EndpointIRODS)
			Expect(err).NotTo(HaveOccurred())

			objPath := path.Join(workColl, "no", "such", "file.txt")
			getURL, err := url.JoinPath(server.EndpointIRODS, objPath)
			Expect(err).NotTo(HaveOccurred())

			r, err = http.NewRequest("GET", getURL, nil)
			Expect(err).NotTo(HaveOccurred())
		}, NodeTimeout(time.Second*2))

		It("should return NotFound", func(ctx SpecContext) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)

			Expect(rec.Code).To(Equal(http.StatusNotFound))
		}, SpecTimeout(time.Second*2))
	})

	When("a valid data object path is given", func() {
		var r *http.Request
		var handler http.Handler
		var err error

		BeforeEach(func(ctx SpecContext) {
			handler, err = testServer.GetHandler(server.EndpointIRODS)
			Expect(err).NotTo(HaveOccurred())

			objPath := path.Join(workColl, testFile)
			getURL, err := url.JoinPath(server.EndpointIRODS, objPath)
			Expect(err).NotTo(HaveOccurred())

			r, err = http.NewRequest("GET", getURL, nil)
			Expect(err).NotTo(HaveOccurred())
		}, NodeTimeout(time.Second*2))

		When("the data object does not have public read permissions", func() {
			It("should return Forbidden", func(ctx SpecContext) {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, r)

				Expect(rec.Code).To(Equal(http.StatusForbidden))
			}, SpecTimeout(time.Second*2))
		})

		When("the data object has public read permissions", func() {
			var conn *connection.IRODSConnection
			var acl []*types.IRODSAccess

			BeforeEach(func(ctx SpecContext) {
				handler, err = testServer.GetHandler(server.EndpointIRODS)
				Expect(err).NotTo(HaveOccurred())

				conn, err = irodsFS.GetIOConnection()
				Expect(err).NotTo(HaveOccurred())

				err = fs.ChangeDataObjectAccess(conn, remotePath, types.IRODSAccessLevelReadObject,
					server.IRODSPublicUser, testZone, false)
				Expect(err).NotTo(HaveOccurred())

				acl, err = irodsFS.ListFileACLsWithGroupUsers(remotePath)
				Expect(err).NotTo(HaveOccurred())

				var publicAccess bool
				for _, ac := range acl {
					suiteLogger.Info().
						Str("user", ac.UserName).
						Str("expected_user", server.IRODSPublicUser).
						Str("zone", ac.UserZone).
						Str("expected_zone", testZone).
						Str("access", ac.AccessLevel.ChmodString()).
						Str("expected_access", types.IRODSAccessLevelReadObject.ChmodString()).
						Msg("ACL")

					if ac.UserName == server.IRODSPublicUser &&
						ac.UserZone == testZone &&
						ac.AccessLevel == types.IRODSAccessLevelReadObject {
						publicAccess = true
					}
				}
				Expect(publicAccess).To(BeTrue())
			}, NodeTimeout(time.Second*5))

			AfterEach(func() {
				irodsFS.ReturnIOConnection(conn)
			})

			It("should return OK", func(ctx SpecContext) {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, r)

				Expect(rec.Code).To(Equal(http.StatusOK))
			}, SpecTimeout(time.Second*2))

			It("should serve the correct body content", func(ctx SpecContext) {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, r)

				Expect(rec.Code).To(Equal(http.StatusOK))
				Expect(rec.Body.String()).To(Equal("test\n"))
			}, SpecTimeout(time.Second*2))
		})
	})
})
