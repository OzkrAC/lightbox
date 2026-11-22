# The lightbox documentation

These pages document lightbox for someone who uses it. Each is a [Luccet](https://luccet.dev) note: an `.html` file whose first line loads `luccet.js` and whose body is Luccet's markup, which the browser renders when the page is opened. There is no build step, and nothing here is generated.

## Files

| File | What it holds |
| --- | --- |
| `index.html` | Home: what lightbox is, what a container is, and the way into the other pages |
| `guide.html` | Getting started: requirements, building, installing, a base, the host network, a first container, the init hook |
| `commands.html` | Every command and option, the values they take, exit statuses, the JSON of `ls`, `inspect` and `doctor`, and the audit log |
| `configuration.html` | `lightbox.conf` and every setting, the environment variables, and a container's `.conf` |
| `storage.html` | Bases and snapshots, overlays and copies, `reset`, volumes, and every file lightbox keeps |
| `networking.html` | The bridge, addresses, `--net`, links, name servers, the firewall with either backend, and a proxy |
| `security.html` | The sandbox piece by piece, user namespaces, and the threat model |
| `agents.html` | The agent profile and how to run an agent's session in a box |
| `internals.html` | The processes behind each command, states, locks, the source tree and the test suites |
| `troubleshooting.html` | `doctor` and each of its checks, what a reboot and a firewall's reload take, what to do about each state, the messages a user meets, and what is left behind |
| `lightbox-docs.js` | The pages' add-on: their vocabulary (callouts, `member`, `::toc`, `::site-nav`), the navigation, the Copy button of every fence, and the release the pages describe |
| `docs.css` | Their look: the layout of Luccet's own documentation, in the colours of Luccet's classic and GitHub themes |
| `.nojekyll` | Tells GitHub Pages to serve the folder as it is |

## The layout

The pages are laid out as Luccet's own documentation is (`docs/` in its repository), from which `docs.css` and `lightbox-docs.js` take their structure and the names of their classes:

- **The navigation** is a sidebar that stays in place on a screen of 64rem or wider, and a bar with a Menu button on a narrower one. It has the name, which leads to the home page, the release the pages describe, the pages in the order of `PAGES`, and under "Project" the links of `PROJECT`. The current page is marked with a bar and `aria-current`.
- **A page's contents** are a card under its title and its opening lines, with the second level of headings on a guide line.
- **The title** stands over a short rule.
- **Every fence has a Copy button**, shown when the fence is pointed at. It copies the code as written. Of a `console` fence it copies the commands alone: the lines that begin with `# ` or `$ `, without the prompt.
- **The colours** are the theme's, through its `--t-*` properties, in the light and in the dark mode. The navigation alone has colours of its own, the `--docs-nav-*` properties at the top of `docs.css`, as it is dark in both. Luccet's own palette and typefaces are its own, and are not used here.

## Reading and checking

Open a page in a browser, from disk or from a server (`python3 -m http.server` in this directory). It loads the engine, two themes and the code add-on from `cdn.luccet.dev`, pinned to their releases, and highlight.js from jsDelivr. Opened from disk or from `localhost`, a page lists its own problems in a panel at the bottom.

With a checkout of [Luccet](https://github.com/Luccet/luccet), which needs Node 22 and nothing else:

```sh
node /path/to/luccet/luccet-cli.js check docs --fail-on=warning
```

checks every page's markup and every link between the pages, anchors included. It reports one `addon.remote` info for each page, for the code add-on, which it does not load; anything else is a problem to fix. Never run an HTML formatter on these files, and never re-wrap their lines: a paragraph, a table row and a heading are each one line.

## Publishing

`.github/workflows/docs.yml` publishes this directory to GitHub Pages on every push to `main` that changes it. The repository's Pages source has to be "GitHub Actions".

## Keeping the pages true

No test reads these pages, as none reads `README.md`: they are kept in step with the binary by hand. A change to a command, an option, a setting, a file, a message or a default is a change to the page that holds it, in the table above, and to the README's command reference.

- **A release.** `VERSION` at the top of `lightbox-docs.js` is the release the pages describe, shown in the navigation of every page. Read the pages against the changelog's section before changing it.
- **A new page.** Copy the first lines of another page, down to `::toc`, add the file to `PAGES` in `lightbox-docs.js`, which puts it in the navigation, and a card to `index.html`, and name it in the table above.
- **A newer Luccet.** The engine's release is in the first line of every page, and the themes' and the code add-on's in its `:::use` block. Change them in every page at once.

## How the pages are written

- **The voice of the README.** Plain sentences that say what lightbox does and what the reader has to do. No sales talk, and nothing about how the text came to be.
- **True to the binary.** Every option, default, limit, message and file name is taken from the source or from a run of the binary, and output shown in a page is real output. A number that a measurement gave, such as a start time, names the release and the host it was measured on.
- **Words.** A *container* everywhere; a *box* for a container of the agent profile and for what `run` makes, as the binary's own messages have it. A *base* is the root filesystem a container is made from, and a *snapshot* lightbox's own copy of one. British spelling.
- **Code spans** for everything that is typed or printed: commands, options, values, paths, settings, system calls. A placeholder is in angle brackets inside the span, as `--mem <limit>`.
- **Commands** are written `lightbox …`, as installed, and run as root unless the text says otherwise. An example that only works with `sudo`, because it names a directory of the user's, has it.
- **Prompts.** In a `console` example `#` is a root shell, and `$` an ordinary user's, with `sudo` where the command needs it. Every command there begins with one of the two and a space, and no line of output does, as the Copy button takes the lines that do for the commands.
- **Ids.** Every heading that is linked to has an id of its own, `{#create}`, and a page's title has `{#top}`. Links between pages name the id: `[exec](commands.html#exec)`.
- **Releases.** What a release changed is said in a sentence, "since 0.8", where a reader with an older container or habit needs it, and not otherwise.

### The constructs

A page begins like every other, down to `::toc`:

````
<!doctype html><html lang="en"><meta charset="utf-8"><title>Storage · lightbox</title><meta name="description" content="…"><script src="https://cdn.luccet.dev/v2.0.0/luccet.js"></script>

:::use
https://cdn.luccet.dev/themes/v1.0.0/classic.css
https://cdn.luccet.dev/themes/v1.0.0/github.css
https://cdn.luccet.dev/code/v1.0.0/code.js
lightbox-docs.js
docs.css
:::

::site-nav

# Storage {#top}

{.brief}
One or two sentences that say what the page covers.

::toc
````

and ends with a `{.source}` paragraph that names the source files behind it. Between the two:

````
### create {#create}

```text{.synopsis}
lightbox create <name> [<ip>] [options]
```

{.ref}
| Option | Default | What it does |
|---|---|---|
| `--mem <limit>` | `256M` | The memory limit |

:::warning[The host is in reach]
A callout: `note`, `tip`, `important`, `warning` or `danger`, with or without a title.
:::

:::member{#conf-subnet}
```ini
subnet = 10.0.0.0/24
```
One entry of a reference, such as a setting, a file or a check: its first fence is its header.
:::
````

- A command's synopsis is a `text` fence with the class `synopsis`.
- A table of options, settings or files has `{.ref}` on the line before it, which keeps its first column on one line.
- Fences name their language: `sh` for commands, `console` for commands with their output, `text` for output alone and for diagrams, `ini` for `lightbox.conf`, `json`, `c`.
- A `|` inside a code span needs no escape in a table; outside one it is `\|`.
