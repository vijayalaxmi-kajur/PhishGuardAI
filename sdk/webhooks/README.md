# PhishGuardAI Moderation Integrations

Pre-built link auditing bots and webhook interceptors for Discord, Slack, and chat communities.

## Overview
Automate phishing defense in your corporate Slack workspaces or Discord gaming/crypto communities. These scripts extract URLs from incoming chat messages in real-time, query the PhishGuardAI API, and issue automated deletion/warning alerts before users can click on malicious links.

---

## 1. Discord PhishGuard Bot

### Quick Test Simulation
```bash
python sdk/webhooks/discord_phish_guard.py --test "Free Nitro gift: http://discord-free-nitro.xyz"
```

### Setup with Discord.py
1. Create a Discord Bot in the [Discord Developer Portal](https://discord.com/developers/applications).
2. Enable `Message Content Intent` in Bot settings.
3. Set your environment variables:
   ```bash
   export PHISHGUARD_API_KEY="pg_live_xxxxxxxxxxxxxxxx"
   export PHISHGUARD_URL="http://127.0.0.1:5000"
   ```
4. Integrate `DiscordPhishGuardAuditor` in your bot's `on_message` event listener:
   ```python
   from discord_phish_guard import DiscordPhishGuardAuditor
   auditor = DiscordPhishGuardAuditor()

   @bot.event
   async def on_message(message):
       if message.author.bot:
           return
       audit = auditor.audit_message(message.content, author_name=str(message.author))
       if audit["action"] == "DELETE_AND_WARN":
           await message.delete()
           await message.channel.send(audit["moderation_alert"])
   ```

---

## 2. Slack Link Auditor

### Quick Test Simulation
```bash
python sdk/webhooks/slack_link_auditor.py --test "Please verify payroll: <http://payroll-adp-login.net|Click here>"
```

### Setup with Slack Bolt
1. Create a Slack App in [api.slack.com/apps](https://api.slack.com/apps).
2. Subscribe to `message.channels` bot events.
3. Integrate `SlackLinkAuditor`:
   ```python
   from slack_link_auditor import SlackLinkAuditor
   auditor = SlackLinkAuditor()

   @app.event("message")
   def handle_message(event, say):
       text = event.get("text", "")
       user = event.get("user", "")
       res = auditor.audit_message(text, user_id=user)
       if res["action"] == "FLAG_AND_REPLY":
           say(blocks=res["slack_blocks"], thread_ts=event.get("ts"))
   ```

