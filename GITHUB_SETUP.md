# GitHub Setup Instructions

## Step 1: Create a GitHub Repository

1. Go to [github.com/new](https://github.com/new)
2. Create a new repository named: **threat-intel-dashboard**
3. Leave it EMPTY (do not initialize with README, .gitignore, or license)
4. Click "Create repository"

## Step 2: Add Remote & Push

Copy and run these commands in your terminal (replace `YOUR_USERNAME` with your actual GitHub username):

```bash
cd "/Users/haim/threat intel/threat-intel-dashboard"

# Add GitHub as remote
git remote add origin https://github.com/YOUR_USERNAME/threat-intel-dashboard.git

# Rename branch to main if needed
git branch -M main

# Push to GitHub
git push -u origin main
```

You'll be prompted for your GitHub credentials. You can use:
- **Username**: Your GitHub username
- **Password**: Your GitHub personal access token (generate at https://github.com/settings/tokens)

## Step 3: Automatic Updates

Every time you make changes to the dashboard and want to sync to GitHub, run:

```bash
cd "/Users/haim/threat intel/threat-intel-dashboard"
git add -A
git commit -m "Description of your changes"
git push
```

## GitHub Workflow for Future Updates

When I make updates to the dashboard based on your requests, here's the automated workflow:

1. Files are edited locally
2. Changes are staged: `git add -A`
3. Changes are committed with descriptive message
4. Changes are pushed to GitHub: `git push`

This ensures your repository is always up-to-date with the latest version.

## Example: Next Update

When you ask for a feature update, I'll:
1. Modify the relevant files (HTML/CSS/JS/Python)
2. Test the changes locally
3. Commit with message like: `git commit -m "Add feature: GreyNoise API integration"`
4. Push to GitHub: `git push`

You can then pull the latest changes anytime:
```bash
git pull origin main
```

## Verify It Works

After pushing to GitHub, verify by:
1. Going to https://github.com/YOUR_USERNAME/threat-intel-dashboard
2. You should see all your files, commits, and commit messages

## Notes

- The `.env` file is in `.gitignore` and will **NOT** be uploaded (secret API keys are safe)
- Only push when the app is working properly
- Always write descriptive commit messages
- Use `git log` to see commit history

---

**Ready to proceed?** Let me know once you've set up the GitHub repo, and I'll automatically push all future changes!
