module.exports = {
    "prefix": "Version ",
    "data-source": "milestones",
    "milestone-match": "Release {{tag_name}}",
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
        "Enhancements:": ["feature", "internal", "build", "documentation"],
        "Bug Fixes:": ["bug"]
    }
};
