import { glob } from 'glob';
import fs from 'fs/promises';

async function addExtensions() {
  const files = await glob('src-ts/**/*.ts');

  for (const file of files) {
    let content = await fs.readFile(file, 'utf8');

    // Add .js to local imports that don't have any extension
    content = content.replace(/from ['"](\.(?:(?!\.js['"])[^'"])*?)['"];/g, "from '$1.js';");

    await fs.writeFile(file, content);
  }
}

addExtensions().catch(console.error);
