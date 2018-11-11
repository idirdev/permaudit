# permaudit

> **[EN]** A CLI tool to audit file and directory permissions, detecting world-writable paths, unexpected executables, and sensitive files exposed to the world.
> **[FR]** Un outil CLI pour auditer les permissions de fichiers et répertoires, détectant les chemins accessibles en écriture par tous, les exécutables inattendus et les fichiers sensibles exposés.

---

## Features / Fonctionnalités

**[EN]**
- Detect world-writable files and directories (permission risk)
- Flag unexpected executable files that are not shell scripts
- Identify sensitive files (.env, .pem, .key, credentials, secrets) readable by all
- Recursive scan with configurable maximum depth
- Skips node_modules and .git automatically
- Exit code 1 when issues are found (CI/CD friendly)

**[FR]**
- Détecter les fichiers et répertoires accessibles en écriture par tous (risque de sécurité)
- Signaler les fichiers exécutables inattendus qui ne sont pas des scripts shell
- Identifier les fichiers sensibles (.env, .pem, .key, credentials, secrets) lisibles par tous
- Scan récursif avec profondeur maximale configurable
- Ignore automatiquement node_modules et .git
- Code de sortie 1 en cas de problème (compatible CI/CD)

---

## Installation

```bash
npm install -g @idirdev/permaudit
```

---

## CLI Usage / Utilisation CLI

```bash
# Audit current directory
# Auditer le répertoire courant
permaudit

# Audit a specific path
# Auditer un chemin spécifique
permaudit /var/www/myapp

# Limit recursion depth to 3 levels
# Limiter la récursion à 3 niveaux
permaudit /var/www/myapp --depth 3

# Show help / Afficher l'aide
permaudit --help
```

### Example Output / Exemple de sortie

```
$ permaudit /var/www/myapp
4 issue(s) found:
[world-writable] /var/www/myapp/uploads (0777)
[world-writable] /var/www/myapp/tmp/cache (0777)
[unexpected-executable] /var/www/myapp/src/utils/helper.js (0755)
[sensitive-world-readable] /var/www/myapp/.env (0644)

$ permaudit /var/www/myapp/src
No permission issues found
```

---

## API (Programmatic) / API (Programmation)

**[EN]** Use permaudit as a library to integrate permission checks into your deployment scripts.
**[FR]** Utilisez permaudit comme bibliothèque pour intégrer les vérifications de permissions dans vos scripts de déploiement.

```javascript
const {
  getPerms,
  isWorldWritable,
  isWorldReadable,
  isExecutable,
  auditDir,
  formatIssues,
} = require('@idirdev/permaudit');

// Get permissions for a single file
// Obtenir les permissions d'un fichier unique
const perms = getPerms('/var/www/myapp/.env');
console.log(perms);
// { path: '/var/www/myapp/.env', mode: '0644', isDir: false,
//   isFile: true, isSymlink: false, uid: 1000, gid: 1000, size: 512 }

// Check specific permission flags
// Vérifier les flags de permission spécifiques
console.log(isWorldWritable('0777')); // true
console.log(isWorldReadable('0644')); // true
console.log(isExecutable('0755'));    // true

// Audit an entire directory tree
// Auditer toute une arborescence de répertoires
const issues = auditDir('/var/www/myapp', { maxDepth: 5 });
if (issues.length) {
  console.error(formatIssues(issues));
  process.exit(1);
}
// [{ path: '/var/www/myapp/uploads', issue: 'world-writable', mode: '0777' }]
```

### API Reference

| Function | Parameters | Returns |
|----------|-----------|---------|
| `getPerms(filePath)` | absolute path | `{path, mode, isDir, isFile, isSymlink, uid, gid, size}` |
| `isWorldWritable(mode)` | octal string | `boolean` |
| `isWorldReadable(mode)` | octal string | `boolean` |
| `isExecutable(mode)` | octal string | `boolean` |
| `auditDir(dir, opts?)` | path, `{maxDepth}` | `Array<{path, issue, mode}>` |
| `formatIssues(issues)` | issues array | `string` |

---

## License

MIT - idirdev
