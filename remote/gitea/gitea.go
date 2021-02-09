// Copyright 2018 Drone.IO Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gitea

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"code.gitea.io/sdk/gitea"
	"github.com/laszlocph/woodpecker/model"
	"github.com/laszlocph/woodpecker/remote"
	"github.com/laszlocph/woodpecker/shared/httputil"
	"github.com/peterhellberg/link"
	"golang.org/x/oauth2"
)

// Opts defines configuration options.
type Opts struct {
	URL         string // Gitea server url.
	Context     string // Context to display in status check
	Client      string   // Gitea oauth client id.
	Secret      string   // Gitea oauth client secret.
	Scopes      []string // Gitea oauth scopes
	RedirectURL string   // Gitea oauth redirect url
	Username    string // Optional machine account username.
	Password    string // Optional machine account password.
	PrivateMode bool   // Gitea is running in private mode.
	SkipVerify  bool   // Skip ssl verification.
}

type client struct {
	URL         string
	Context     string
	Client      string
	Secret      string
	Scopes      []string
	RedirectURL string
	Machine     string
	Username    string
	Password    string
	PrivateMode bool
	SkipVerify  bool
}

const (
	DescPending  = "the build is pending"
	DescRunning  = "the build is running"
	DescSuccess  = "the build was successful"
	DescFailure  = "the build failed"
	DescCanceled = "the build canceled"
	DescBlocked  = "the build is pending approval"
	DescDeclined = "the build was rejected"
)

// getStatus is a helper function that converts a Drone
// status to a Gitea status.
func getStatus(status string) gitea.StatusState {
	switch status {
	case model.StatusPending, model.StatusBlocked:
		return gitea.StatusPending
	case model.StatusRunning:
		return gitea.StatusPending
	case model.StatusSuccess:
		return gitea.StatusSuccess
	case model.StatusFailure, model.StatusError:
		return gitea.StatusFailure
	case model.StatusKilled:
		return gitea.StatusFailure
	case model.StatusDeclined:
		return gitea.StatusWarning
	default:
		return gitea.StatusFailure
	}
}

// getDesc is a helper function that generates a description
// message for the build based on the status.
func getDesc(status string) string {
	switch status {
	case model.StatusPending:
		return DescPending
	case model.StatusRunning:
		return DescRunning
	case model.StatusSuccess:
		return DescSuccess
	case model.StatusFailure, model.StatusError:
		return DescFailure
	case model.StatusKilled:
		return DescCanceled
	case model.StatusBlocked:
		return DescBlocked
	case model.StatusDeclined:
		return DescDeclined
	default:
		return DescFailure
	}
}

// New returns a Remote implementation that integrates with Gitea, an open
// source Git service written in Go. See https://gitea.io/
func New(opts Opts) (remote.Remote, error) {
	url, err := url.Parse(opts.URL)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(url.Host)
	if err == nil {
		url.Host = host
	}
	return &client{
		URL:         opts.URL,
		Context:     opts.Context,
		Client:      opts.Client,
		Secret:      opts.Secret,
		Scopes:      opts.Scopes,
		Machine:     url.Host,
		Username:    opts.Username,
		Password:    opts.Password,
		PrivateMode: opts.PrivateMode,
		SkipVerify:  opts.SkipVerify,
	}, nil
}

// Login authenticates an account with Gitea using either OAuth2 or basic authentication. The
// Gitea account details are returned when the user is successfully authenticated.
func (c *client) Login(res http.ResponseWriter, req *http.Request) (*model.User, error) {

	if len(c.Client) == 0 || len(c.Secret) == 0 {
		// fall back to basic auth
		return c.LoginBasicAuth(res, req)
	}

	return c.LoginOAuth(res, req)
}

// LoginOAuth authenticates an account with Gitea using OAuth2. The
// Gitea account details are returned when the user is successfully authenticated.
func (c *client) LoginOAuth(res http.ResponseWriter, req *http.Request) (*model.User, error) {
	config := c.newOAuth2Config(req)

	// get the OAuth errors
	if err := req.FormValue("error"); err != "" {
		return nil, &remote.AuthError{
			Err:         err,
			Description: req.FormValue("error_description"),
			URI:         req.FormValue("error_uri"),
		}
	}

	// get the OAuth code
	code := req.FormValue("code")
	if len(code) == 0 {
		// TODO(bradrydzewski) we really should be using a random value here and
		// storing in a cookie for verification in the next stage of the workflow.

		http.Redirect(res, req, config.AuthCodeURL("drone"), http.StatusSeeOther)
		return nil, nil
	}

	token, err := config.Exchange(c.newContext(), code)
	if err != nil {
		return nil, err
	}

	client, err := c.newClientToken(token.AccessToken)
	if err != nil {
		return nil, err
	}
	
	account, _, err := client.GetMyUserInfo()
	if err != nil {
		return nil, err
	}

	return &model.User{
		Token:  token.AccessToken,
		Login:  account.UserName,
		Email:  account.Email,
		Avatar: expandAvatar(c.URL, account.AvatarURL),
	}, nil
}

// LoginBasicAuth authenticates an account with Gitea using basic authentication. The
// Gitea account details are returned when the user is successfully authenticated.
func (c *client) LoginBasicAuth(res http.ResponseWriter, req *http.Request) (*model.User, error) {
	var (
		username = req.FormValue("username")
		password = req.FormValue("password")
	)

	// if the username or password is empty we re-direct to the login screen.
	if len(username) == 0 || len(password) == 0 {
		http.Redirect(res, req, "/login/form", http.StatusSeeOther)
		return nil, nil
	}

	client, err := c.newClientToken("")
	if err != nil {
		return nil, err
	}

	// since api does not return token secret, if drone token exists create new one
	client.SetBasicAuth(username, password)
	resp, err := client.DeleteAccessToken("drone")
	if err != nil && !(resp != nil && resp.StatusCode == 404) {
		return nil, err
	}

	token, _, terr := client.CreateAccessToken(
		gitea.CreateAccessTokenOption{Name: "drone"},
	)
	if terr != nil {
		return nil, terr
	}
	accessToken := token.Token

	client, err = c.newClientToken(accessToken)
	if err != nil {
		return nil, err
	}
	account, _, err := client.GetUserInfo(username)
	if err != nil {
		return nil, err
	}

	return &model.User{
		Token:  accessToken,
		Login:  account.UserName,
		Email:  account.Email,
		Avatar: expandAvatar(c.URL, account.AvatarURL),
	}, nil
}

// Auth is not supported by the Gitea driver.
func (c *client) Auth(token, secret string) (string, error) {
	return "", fmt.Errorf("Not Implemented")
}

// Teams is supported by the Gitea driver.
func (c *client) Teams(u *model.User) ([]*model.Team, error) {
	client, err := c.newClientToken(u.Token)
	if err != nil {
		return nil, err
	}

	orgs, _, err := client.ListMyOrgs(gitea.ListOrgsOptions{})
	if err != nil {
		return nil, err
	}

	var teams []*model.Team
	for _, org := range orgs {
		teams = append(teams, toTeam(org, c.URL))
	}
	return teams, nil
}

// TeamPerm is not supported by the Gitea driver.
func (c *client) TeamPerm(u *model.User, org string) (*model.Perm, error) {
	return nil, nil
}

// Repo returns the named Gitea repository.
func (c *client) Repo(u *model.User, owner, name string) (*model.Repo, error) {
	client, err := c.newClientToken(u.Token)
	if err != nil {
		return nil, err
	}

	repo, _, err := client.GetRepo(owner, name)
	if err != nil {
		return nil, err
	}
	if c.PrivateMode {
		repo.Private = true
	}
	return toRepo(repo, c.PrivateMode), nil
}

// Repos returns a list of all repositories for the Gitea account, including
// organization repositories.
func (c *client) Repos(u *model.User) ([]*model.Repo, error) {
	repos := []*model.Repo{}

	client, err := c.newClientToken(u.Token)
	if err != nil {
		return nil, err
	}

	const maxPages = 10 //this means max 500 repos

	for page := 1; page <= maxPages; page++ {
		all, more, err := reposPage(client, page)
	if err != nil {
		return repos, err
	}

	for _, repo := range all {
		repos = append(repos, toRepo(repo, c.PrivateMode))
	}
		if !more {
			break
		}
	}
	
	return repos, err
}

// reposPage is a helper function to do pagination for repository listing
func reposPage(client *gitea.Client, page int) ([]*gitea.Repository, bool, error) {
	opts := gitea.ListReposOptions{
		ListOptions: gitea.ListOptions {
			PageSize: 50, //maxPageSize from gitea client
			Page: page,
		},
	}
	more := false

	all, resp, err := client.ListMyRepos(opts)
	if err != nil {
		return nil, more, err
	}

	for _, l := range link.ParseResponse(resp.Response) {
		if l.Rel == "next" {
			more = true
			break
		}
	}	

	return all, more, nil
}

// Perm returns the user permissions for the named Gitea repository.
func (c *client) Perm(u *model.User, owner, name string) (*model.Perm, error) {
	client, err := c.newClientToken(u.Token)
	if err != nil {
		return nil, err
	}

	repo, _, err := client.GetRepo(owner, name)
	if err != nil {
		return nil, err
	}
	return toPerm(repo.Permissions), nil
}

// File fetches the file from the Gitea repository and returns its contents.
func (c *client) File(u *model.User, r *model.Repo, b *model.Build, f string) ([]byte, error) {
	client, err := c.newClientToken(u.Token)
	if err != nil {
		return nil, err
	}

	cfg, _, err := client.GetFile(r.Owner, r.Name, b.Commit, f)
	return cfg, err
}

func (c *client) Dir(u *model.User, r *model.Repo, b *model.Build, f string) ([]*remote.FileMeta, error) {
	return nil, fmt.Errorf("Not implemented")
}

// Status is supported by the Gitea driver.
func (c *client) Status(u *model.User, r *model.Repo, b *model.Build, link string, proc *model.Proc) error {
	client, err := c.newClientToken(u.Token)
	if err != nil {
		return err
	}

	status := getStatus(b.Status)
	desc := getDesc(b.Status)

	_, _, err = client.CreateStatus(
		r.Owner,
		r.Name,
		b.Commit,
		gitea.CreateStatusOption{
			State:       status,
			TargetURL:   link,
			Description: desc,
			Context:     c.Context,
		},
	)

	return err
}

// Netrc returns a netrc file capable of authenticating Gitea requests and
// cloning Gitea repositories. The netrc will use the global machine account
// when configured.
func (c *client) Netrc(u *model.User, r *model.Repo) (*model.Netrc, error) {
	if c.Password != "" {
		return &model.Netrc{
			Login:    c.Username,
			Password: c.Password,
			Machine:  c.Machine,
		}, nil
	}
	return &model.Netrc{
		Login:    u.Login,
		Password: u.Token,
		Machine:  c.Machine,
	}, nil
}

// Activate activates the repository by registering post-commit hooks with
// the Gitea repository.
func (c *client) Activate(u *model.User, r *model.Repo, link string) error {
	config := map[string]string{
		"url":          link,
		"secret":       r.Hash,
		"content_type": "json",
	}
	hook := gitea.CreateHookOption{
		Type:   "gitea",
		Config: config,
		Events: []string{"push", "create", "pull_request"},
		Active: true,
	}

	client, err := c.newClientToken(u.Token)
	if err != nil {
		return err
	}
	_, _, err = client.CreateRepoHook(r.Owner, r.Name, hook)
	return err
}

// Deactivate deactives the repository be removing repository push hooks from
// the Gitea repository.
func (c *client) Deactivate(u *model.User, r *model.Repo, link string) error {
	client, err := c.newClientToken(u.Token)
	if err != nil {
		return err
	}

	hooks, _, err := client.ListRepoHooks(r.Owner, r.Name, gitea.ListHooksOptions{})
	if err != nil {
		return err
	}

	hook := matchingHooks(hooks, link)
	if hook != nil {
		_, err := client.DeleteRepoHook(r.Owner, r.Name, hook.ID)
		return err
	}

	return nil
}

// Hook parses the incoming Gitea hook and returns the Repository and Build
// details. If the hook is unsupported nil values are returned.
func (c *client) Hook(r *http.Request) (*model.Repo, *model.Build, error) {
	return parseHook(r)
}

// helper function to return the Gitea client
func (c *client) newClientToken(token string) (*gitea.Client, error) {
	httpClient := &http.Client{}

	// basic auth
	if len(c.Client) == 0 || len(c.Secret) == 0 {		
		if c.SkipVerify {
			httpClient.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
	} else {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		httpClient = oauth2.NewClient(oauth2.NoContext, ts)
		if c.SkipVerify {
			httpClient.Transport.(*oauth2.Transport).Base = &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			}
		}
	}

	return gitea.NewClient(c.URL, gitea.SetToken(token), gitea.SetHTTPClient(httpClient))
}

// helper function to return the Gitea oauth2 context using an HTTPClient that
// disables TLS verification if disabled in the remote settings.
func (c *client) newContext() context.Context {
	if !c.SkipVerify {
		return oauth2.NoContext
	}
	return context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	})
}

// helper function to return the Gitea oauth2 config
func (c *client) newOAuth2Config(req *http.Request) *oauth2.Config {
	redirect := fmt.Sprintf("%s/authorize", httputil.GetURL(req))

	return &oauth2.Config{
		ClientID:     c.Client,
		ClientSecret: c.Secret,
		Scopes:       c.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/login/oauth/authorize", c.URL),
			TokenURL: fmt.Sprintf("%s/login/oauth/access_token", c.URL),
		},
		RedirectURL: redirect,
	}
}

// helper function to return matching hooks.
func matchingHooks(hooks []*gitea.Hook, rawurl string) *gitea.Hook {
	link, err := url.Parse(rawurl)
	if err != nil {
		return nil
	}
	for _, hook := range hooks {
		if val, ok := hook.Config["url"]; ok {
			hookurl, err := url.Parse(val)
			if err == nil && hookurl.Host == link.Host {
				return hook
			}
		}
	}
	return nil
}
