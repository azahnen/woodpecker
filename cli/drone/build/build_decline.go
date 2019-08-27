package build

import (
	"fmt"
	"strconv"

	"github.com/laszlocph/woodpecker/cli/drone/internal"
	"github.com/urfave/cli"
)

var buildDeclineCmd = cli.Command{
	Name:      "decline",
	Usage:     "decline a build",
	ArgsUsage: "<repo/name> <build>",
	Action:    buildDecline,
}

func buildDecline(c *cli.Context) (err error) {
	repo := c.Args().First()
	owner, name, err := internal.ParseRepo(repo)
	if err != nil {
		return err
	}
	number, err := strconv.Atoi(c.Args().Get(1))
	if err != nil {
		return err
	}

	client, err := internal.NewClient(c)
	if err != nil {
		return err
	}

	_, err = client.BuildDecline(owner, name, number)
	if err != nil {
		return err
	}

	fmt.Printf("Declining build %s/%s#%d\n", owner, name, number)
	return nil
}
