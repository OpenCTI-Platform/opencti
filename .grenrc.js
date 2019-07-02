module.exports = {
    "prefix": "Version ",
    "ignoreIssuesWith": [
        "duplicate",
        "wontfix",
        "invalid",
        "help wanted"
    ],
    "template": {
        "issue": "- [{{text}}]({{url}}) {{name}}"
    },
    "groupBy": {
        "Enhancements:": ["feature", "internal"],
        "Bug Fixes:": ["bug"]
    }
};
