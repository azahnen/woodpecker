import React, { Component } from "react";
import Menu from "shared/components/menu";

export default class RepoMenu extends Component {
  render() {
    const { owner, repo } = this.props.match.params;
    const { user } = this.props;
    const menu =
      user && user.data
        ? [
            { to: `/${owner}/${repo}`, label: "Builds" },
            { to: `/${owner}/${repo}/settings/secrets`, label: "Secrets" },
            { to: `/${owner}/${repo}/settings/registry`, label: "Registry" },
            { to: `/${owner}/${repo}/settings`, label: "Settings" },
          ]
        : [{ to: `/${owner}/${repo}`, label: "Builds" }];

    return <Menu items={menu} {...this.props} />;
  }
}
