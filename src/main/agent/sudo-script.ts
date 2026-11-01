/**
 * Builds the /bin/sh script used to run a model-written command that contains
 * `sudo`, with the user's password supplied on the shell's stdin.
 *
 * Writing the password to the stdin of the whole command is unsafe: any other
 * program in the command (`head -n1; sudo ls`), or the command after a sudo
 * that found cached credentials and never read stdin, can read the password and
 * return it in the tool output that goes to the model provider.
 *
 * The script instead:
 *   1. lets `sudo -S -v` alone read the password (sudo reads it byte by byte up
 *      to the newline, so nothing else is buffered away),
 *   2. replaces the shell's stdin with /dev/null, dropping whatever is left in
 *      the pipe (the whole password when sudo already had cached credentials),
 *   3. runs the original command with every `sudo` turned into `sudo -n`, which
 *      uses the credentials cached by step 1 and never prompts.
 *
 * If the cached credentials are not usable (for example `timestamp_timeout=0`
 * in sudoers, or a sudo started from a subshell), `sudo -n` fails with
 * "a password is required" instead of leaking anything.
 */
export function buildSudoScript(command: string): string {
  const rewritten = command.replace(/\bsudo\b/g, 'sudo -n');
  return ["sudo -S -p '' -v || exit 1", 'exec 0</dev/null', rewritten].join('\n');
}
