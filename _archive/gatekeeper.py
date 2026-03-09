import discord
from discord.ext import commands, tasks
from discord.ui import Button, View
import os
import asyncio
import sys
import json
import time
from dotenv import load_dotenv

# Load hidden file credentials explicitly 
load_dotenv()

# Define Role-Based Profiles for Zero Trust JIT Access
ROLES = {
    "E-1": ["ls", "cd", "cat", "echo", "pwd"],
    "E-2": ["git", "curl", "wget", "ps", "top"],
    "E-3": ["docker", "kubectl", "systemctl", "journalctl"],
    "E-4": ["sudo", "chmod", "chown", "rm", "mount"]
}

# Dummy user state to simulate our local session
local_session = {
    "user": "adityasingh",
    "base_level": "E-1",
    "current_level": "E-1",
    "permissions": ROLES["E-1"].copy(),
    "is_elevated": False
}

# --- Discord Bot Setup ---
DISCORD_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
admin_channel_str = os.getenv("ADMIN_CHANNEL_ID")

if not DISCORD_TOKEN or not admin_channel_str:
    print("[ERROR] Cannot find DISCORD_BOT_TOKEN or ADMIN_CHANNEL_ID in your .env file!", file=sys.stderr)
    print("Please ensure your .env file is formatted correctly (e.g. DISCORD_BOT_TOKEN=MTE5...)", file=sys.stderr)
    sys.exit(1)

try:
    ADMIN_CHANNEL_ID = int(admin_channel_str)
except ValueError:
    print("[ERROR] ADMIN_CHANNEL_ID in your .env file must be a valid integer ID!", file=sys.stderr)
    sys.exit(1)

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

class ApprovalView(View):
    def __init__(self, target_level, user):
        super().__init__()
        self.timeout = 300 # 5 minute timeout
        self.target_level = target_level
        self.requesting_user = user

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.green, custom_id="approve_jit")
    async def approve_button(self, interaction: discord.Interaction, button: Button):
        # 1. Update the local session AND access_ledger.json
        local_session["is_elevated"] = True
        local_session["current_level"] = self.target_level
        local_session["permissions"] = ROLES[self.target_level].copy()
        
        try:
            with open("access_ledger.json", "r") as f:
                data = json.load(f)
            data["current_level"] = self.target_level
            data["status"] = "UNLOCKED"
            data["expiry"] = time.time() + 300
            
            with open("access_ledger.json", "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"[Error] Failed to update ledger: {e}")
        
        # 2. Update the UI
        for child in self.children:
            child.disabled = True
            
        embed = interaction.message.embeds[0]
        embed.color = discord.Color.green()
        embed.add_field(name="Status", value=f"✅ Approved by {interaction.user.mention}", inline=False)
        
        await interaction.response.edit_message(embed=embed, view=self)
        print(f"\n[JIT Workflow] 🟢 Access Granted! {self.requesting_user} elevated to {self.target_level} by {interaction.user.name}.")
        print_local_status()
        
        # 3. Auto-revocation is handled by the check_expiry background task

    @discord.ui.button(label="Decline", style=discord.ButtonStyle.red, custom_id="decline_jit")
    async def decline_button(self, interaction: discord.Interaction, button: Button):
        for child in self.children:
            child.disabled = True
            
        embed = interaction.message.embeds[0]
        embed.color = discord.Color.red()
        embed.add_field(name="Status", value=f"❌ Declined by {interaction.user.mention}", inline=False)
        
        try:
            with open("access_ledger.json", "r") as f:
                data = json.load(f)
            data["status"] = "LOCKED"
            with open("access_ledger.json", "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"[Error] Failed to update ledger to LOCKED: {e}")
            
        await interaction.response.edit_message(embed=embed, view=self)
        print(f"\n[JIT Workflow] 🔴 Access Denied! {self.requesting_user} remains at {local_session['base_level']}.")

def print_local_status():
    print(f"[Local System] User: {local_session['user']} | Active Level: {local_session['current_level']}")
    print(f"🔒 Permissions: {', '.join(local_session['permissions'])}")

@tasks.loop(seconds=5.0)
async def check_expiry():
    """Background task to watch access_ledger.json for expiration."""
    try:
        with open("access_ledger.json", "r") as f:
            data = json.load(f)
            
        if data.get("status") == "UNLOCKED" and data.get("expiry"):
            if time.time() > data.get("expiry"):
                print(f"\n[Session] 🔄 JIT time expired! Terminating session for {local_session['user']}...")
                
                local_session["is_elevated"] = False
                local_session["current_level"] = local_session["base_level"]
                local_session["permissions"] = ROLES[local_session["base_level"]].copy()
                print_local_status()
                
                data["status"] = "LOCKED"
                data["expiry"] = None
                data["current_level"] = local_session["base_level"]
                
                with open("access_ledger.json", "w") as f:
                    json.dump(data, f, indent=4)
                
                channel = bot.get_channel(ADMIN_CHANNEL_ID)
                if channel:
                    await channel.send(f"🕒 **JIT Access Expired:** `{local_session['user']}` has been reverted to **E-1** baseline.")
    except Exception:
        pass


@tasks.loop(seconds=1.0)
async def check_ledger():
    """Background task to watch for gatekeeper_cli.py triggering an automated !request_e4 workflow."""
    try:
        with open("access_ledger.json", "r") as f:
            data = json.load(f)
            
        if data.get("status") == "PENDING":
            # Switch to awaiting to prevent Discord api spam
            data["status"] = "AWAITING_APPROVAL"
            with open("access_ledger.json", "w") as f:
                json.dump(data, f, indent=4)
                
            user = local_session["user"]
            target = "E-4"
            
            print(f"\n[🛡️ CLI TRIGGER] 🟡 Unauthorized local execution intercepted! Dispatching Request...")
            
            embed = discord.Embed(
                title="⚠️ Just-In-Time Access Request",
                description=f"**User `{user}`** triggered a blocked command via CLI and requests elevation.",
                color=discord.Color.gold()
            )
            embed.add_field(name="Current Level", value=local_session["current_level"], inline=True)
            embed.add_field(name="Requested Level", value=target, inline=True)
            embed.add_field(name="Trigger Source", value="`gatekeeper_cli.py` interception", inline=False)
            embed.set_footer(text="Sentinel-AI Gatekeeper • Zero Trust IAM")

            view = ApprovalView(target_level=target, user=user)
            admin_channel = bot.get_channel(ADMIN_CHANNEL_ID)
            
            if admin_channel:
                 await admin_channel.send(embed=embed, view=view)
    except Exception:
        pass

@bot.event
async def on_ready():
    print(f"\n🛡️ Gatekeeper Bot logged in as {bot.user}")
    print("Zero Trust IAM Platform Online. Local status:")
    print_local_status()
    print("\nTo simulate a request manually, type `!request_e4` in Discord, or let gatekeeper_cli.py auto-trigger the bot via ledger.")
    
    if not check_ledger.is_running():
        check_ledger.start()
    if not check_expiry.is_running():
        check_expiry.start()


@bot.command(name="request_e4")
async def request_elevation(ctx):
    """Simulates the local pipeline requesting JIT elevation via Discord."""
    user = local_session["user"]
    target = "E-4"
    
    print(f"\n[JIT Workflow] 🟡 {user} requesting elevation: E-1 -> E-4. Waiting for Discord approval...")
    
    embed = discord.Embed(
        title="⚠️ Just-In-Time Access Request",
        description=f"**User `{user}`** is requesting temporary elevated privileges.",
        color=discord.Color.gold()
    )
    embed.add_field(name="Current Level", value=local_session["current_level"], inline=True)
    embed.add_field(name="Requested Level", value=target, inline=True)
    embed.add_field(name="Requested Permissions", value=f"`{', '.join(ROLES[target])}`", inline=False)
    embed.set_footer(text="Sentinel-AI Gatekeeper • Zero Trust IAM")

    view = ApprovalView(target_level=target, user=user)
    
    # 1. Fetch the private admin channel
    admin_channel = bot.get_channel(ADMIN_CHANNEL_ID)
    
    if admin_channel:
        # 2. Add debug log to terminal
        print(f"[DEBUG] Sending request to Channel ID: {ADMIN_CHANNEL_ID}")
        # 3. Send securely to admin channel
        await admin_channel.send(embed=embed, view=view)
        # 4. Give public ephemeral text feedback
        await ctx.send("✅ Request Sent to Administrators.", delete_after=5.0)
    else:
        print(f"[ERROR] Could not find Admin Channel {ADMIN_CHANNEL_ID}. Ensure the bot has access to it.", file=sys.stderr)
        await ctx.send("❌ Error: Administrator channel missing or unreachable.", delete_after=10.0)

# Remove any accidental on_message listeners that could cause double-execution
# Since we are using commands.Bot, the command decorator handles the message natively
bot.remove_listener(bot.on_message)

if __name__ == "__main__":
    try:
        bot.run(DISCORD_TOKEN)
    except discord.errors.LoginFailure:
        print("[ERROR] Invalid Bot Token provided in .env.", file=sys.stderr)
        sys.exit(1)
