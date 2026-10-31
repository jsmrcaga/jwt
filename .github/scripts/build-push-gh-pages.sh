#!/usr/bin/env bash
set -e

ORIGIN_NAME=${1:-origin}
BRANCH_NAME=${2:-gh-pages}
DESTINATION_DIRECTORY=${3:-site}
ORIGIN_DIRECTORY=${4:-jsdoc}
VERSION=$5

if [[ -z $VERSION ]]; then
	echo "Version is mandatory" >&2
	exit 1
fi

# Git config for GitHub Actions
git config --global user.name  "github-actions[bot]"
git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com"

# Remove worktree if already exists
git worktree remove --force "$DESTINATION_DIRECTORY" 2> /dev/null || true
# Check if the branch exists
if git fetch --depth=1 $ORIGIN_NAME $BRANCH_NAME 2> /dev/null; then
	git worktree add -B $BRANCH_NAME "$DESTINATION_DIRECTORY" FETCH_HEAD
else
	git worktree add --orphan -b $BRANCH_NAME "$DESTINATION_DIRECTORY"
fi

tmp_file=$(mktemp)
# Generate versions.json
if [ -s "$DESTINATION_DIRECTORY/versions.json" ]; then
    versions=$(cat "$DESTINATION_DIRECTORY/versions.json")
else
    versions='{"versions": []}'
fi

echo $versions | jq --arg v "$VERSION" '.versions=([$v] + .versions | unique)' > "$tmp_file" \
	&& mv "$tmp_file" "$DESTINATION_DIRECTORY/versions.json"

cat "$DESTINATION_DIRECTORY/versions.json"

# Generate docs
VERSION=$VERSION  JSDOC_BASE_PATH="/jwt/latest" npm run docs:build
	# try removing latest to make sure we replace it
rm -r "$DESTINATION_DIRECTORY/latest" || true
cp -r $ORIGIN_DIRECTORY "$DESTINATION_DIRECTORY/latest"

VERSION=$VERSION JSDOC_BASE_PATH="/jwt/$VERSION" npm run docs:build
cp -r $ORIGIN_DIRECTORY "$DESTINATION_DIRECTORY/$VERSION"

# Copy versions into the latest/vX.X.X directories
cp "$DESTINATION_DIRECTORY/versions.json" "$DESTINATION_DIRECTORY/$VERSION/versions.json"
cp "$DESTINATION_DIRECTORY/versions.json" "$DESTINATION_DIRECTORY/latest/versions.json"

# Push docs
# move to gh-pages branch in worktree
cd $DESTINATION_DIRECTORY
echo "Adding $VERSION & /latest"
git add "$VERSION" "latest" "versions.json"

echo "Committing $VERSION"
git commit -m "docs: $VERSION"

echo "Pushing to $ORIGIN_NAME $BRANCH_NAME"
git push $ORIGIN_NAME $BRANCH_NAME

echo "Removing worktree $DESTINATION_DIRECTORY"
git worktree remove "$DESTINATION_DIRECTORY"

echo "Done"
