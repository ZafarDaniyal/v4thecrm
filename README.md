# Insurance CRM Tracker

A lightweight shared CRM for insurance sales teams.

## What it includes

- Shared login for 4 salespeople + owner
- Sales entry fields: customer name, phone number, address, date sold, exact premium amount
- Monthly sales log and leaderboard
- Owner-only hidden analytics sheet
  - total premium sold
  - total agent commissions
  - total agency commissions (what comes to the business)
- Owner CSV upload and monthly CSV export
- Competition mode toggle
  - ON: everyone can see all sales and leaderboard
  - OFF: each salesperson sees only their own data

## Default users

- Owner: `owner / owner123!`
- Salespeople: `sales1`, `sales2`, `sales3`, `sales4` with passcode `agent123!`

## Run locally

```bash
cd "/Users/daniyalzafar/Documents/New project"
python3 app.py
```

Open [http://localhost:8080](http://localhost:8080).

## Data storage

SQLite database file:

- `/Users/daniyalzafar/Documents/New project/data/crm.db`

## Quick demo data

- In Owner Sheet, download `Sample Data CSV` and upload it.
- This loads realistic policy sales for all 4 salespeople so leaderboard and commissions are populated.

## Notes

- Change default passcodes before production use.
- This is designed for internal team usage and can be deployed behind your own hosting/login controls.

## Deploy free on Render (public URL)

1. Put this folder in a GitHub repo.
2. Go to [Render Dashboard](https://dashboard.render.com/) and click **New +** -> **Blueprint**.
3. Connect the GitHub repo.
4. Render will detect `render.yaml` and create the web service.
5. Wait for deploy, then open the `https://...onrender.com` URL.

### Deploy behavior for demo/testing

- Great for letting your friend tinker and even break data.
- SQLite data can reset on redeploy or instance changes, so treat this as a demo/staging environment.
- Default credentials are still active on first deploy, so change passcodes before wider sharing.
