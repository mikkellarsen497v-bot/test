# SAM (Simple Admin Mod) — Commands Reference

All commands are run in the **game console** (or via the in-game SAM menu) with the prefix **`sam`**.

**Syntax:** `sam <command> [arguments]`

---

## Opening the menu

| Command | Description |
|--------|--------------|
| `sam menu` | Open the SAM admin menu (same as the in-game menu). |

---

## Bans (what your website reads from the database)

| Command | Description | Example |
|--------|--------------|---------|
| `sam ban <player> [length] [reason]` | Ban a player. Length in minutes; 0 = permanent. | `sam ban "PlayerName" 1440 RDM` |
| `sam banid <steamid> [length] [reason]` | Ban by SteamID (e.g. offline players). | `sam banid STEAM_0:0:123456 10080 MRDM` |
| `sam unban <steamid>` | Unban a player by SteamID. | `sam unban STEAM_0:0:123456` |

**Length examples:** `60` = 1 min, `1440` = 1 day, `10080` = 7 days, `43200` = 30 days, `0` = permanent.

---

## Kicks & utility

| Command | Description |
|--------|--------------|
| `sam kick <player> [reason]` | Kick a player. |
| `sam map <mapname> [gamemode]` | Change map (and optional gamemode). |
| `sam maprestart` | Restart the current map. |
| `sam mapreset` | Reset the map. |
| `sam noclip [player]` | Toggle noclip for you or a player. |
| `sam cleardecals` | Clear ragdolls and decals for everyone. |
| `sam stopsound` | Stop all sounds for everyone. |

---

## User management (ranks)

| Command | Description |
|--------|--------------|
| `sam setrank <player> <rank> [length]` | Set a player’s rank (aliases: adduser, changerank, giverank). |
| `sam setrankid <steamid> <rank> [length]` | Set rank by SteamID. |
| `sam addrank <name> <inherit_from> [immunity] [ban_limit]` | Create a new rank. |
| `sam removerank <rank>` | Remove a rank. |
| `sam renamerank <rank> <new_name>` | Rename a rank. |
| `sam givepermission <rank> <permission>` | Give a permission to a rank. |
| `sam takepermission <rank> <permission>` | Remove a permission from a rank. |
| `sam changeinherit <rank> <inherit_from>` | Change which rank a rank inherits from. |
| `sam changerankimmunity <rank> <value>` | Set rank immunity (2–99). |
| `sam changerankbanlimit <rank> <minutes>` | Set max ban length for that rank. |

---

## Chat

| Command | Description |
|--------|--------------|
| `sam pm <player> <message>` | Send a private message. |
| `sam asay <message>` | Send a message to admins (or create a report if not admin). |
| `sam mute <player> [length] [reason]` | Mute a player in chat. |
| `sam unmute <player>` | Unmute a player. |
| `sam gag <player> [length] [reason]` | Gag a player (no voice). |
| `sam ungag <player>` | Ungag a player. |

---

## Fun / punishment

| Command | Description |
|--------|--------------|
| `sam slap <player> [damage]` | Slap a player (optional damage). |
| `sam slay <player>` | Kill a player. |
| `sam hp <player> [amount]` | Set health (default 100). |
| `sam armor <player> [amount]` | Set armor (aliases: setarmor). |
| `sam ignite <player> [seconds]` | Set a player on fire. |
| `sam unignite <player>` | Extinguish a player. |
| `sam god <player>` | Enable god mode. |
| `sam ungod <player>` | Disable god mode. |
| `sam freeze <player>` | Freeze a player. |
| `sam unfreeze <player>` | Unfreeze a player. |
| `sam cloak <player>` | Make a player invisible. |
| `sam uncloak <player>` | Make a player visible. |
| `sam jail <player> [length] [reason]` | Jail a player. |
| `sam unjail <player>` | Unjail a player. |
| `sam strip <player>` | Remove all weapons. |
| `sam respawn <player>` | Respawn a player. |
| `sam setmodel <player> <model>` | Change a player’s model. |
| `sam scale <player> <scale>` | Scale a player’s model. |
| `sam buddha <player>` | Buddha mode (can’t go below 1 HP). |
| `sam unbuddha <player>` | Turn off buddha mode. |
| `sam give <player> <weapon/entity>` | Give a weapon or entity. |
| `sam freezeprops` | Freeze all props on the map. |

---

## Teleport

| Command | Description |
|--------|--------------|
| `sam bring <player>` | Teleport a player to you. |
| `sam goto <player>` | Teleport yourself to a player. |
| `sam return <player>` | Send a player back to their previous location. |

---

## Other

| Command | Description |
|--------|--------------|
| `sam time [player]` | Show your or a player’s total play time. |
| `sam admin` | Turn on admin mode (e.g. noclip). |
| `sam unadmin` | Turn off admin mode. |
| `sam exitvehicle <player>` | Force a player out of their vehicle. |
| `sam giveammo <player>` | Give ammo to a player. |

---

## DarkRP (if you use DarkRP)

| Command | Description |
|--------|--------------|
| `sam arrest <player> [seconds]` | Arrest a player. |
| `sam unarrest <player>` | Unarrest a player. |
| `sam setmoney <player> <amount>` | Set a player’s money. |
| `sam addmoney <player> <amount>` | Add money to a player. |
| `sam setjob <player> <job>` | Set a player’s job. |
| `sam forcename <player> <name>` | Force a player’s name. |
| `sam setjailpos` | Set jail position at your location. |
| `sam addjailpos` | Add a jail position. |
| `sam selldoor` | Sell the door/vehicle you’re looking at. |
| `sam sellall <player>` | Sell all doors/vehicles for a player. |
| `sam shipment <name>` | Spawn a shipment. |

---

## Console usage

- Open the console with **`~`** (tilde) in-game.
- Type e.g. `sam ban "PlayerName" 1440 RDM` then press Enter.
- For **permanent ban:** use `0` for length: `sam ban "Name" 0 Reason`.
- Player names with spaces: use quotes: `sam kick "Some Player" reason`.

Your **bans page** on the website reads from the same database these ban commands write to (`sam_bans` table), so any ban you do with `sam ban` or `sam banid` will show there once the connection is working.
