import { execSync } from 'child_process';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

async function compileProtobuf() {
  try {
    if (!existsSync(resolve(projectRoot, 'proto/whisper.proto'))) {
      throw new Error('whisper.proto file not found');
    }

    console.log('🔄 Generating JavaScript code...');
    execSync(`yarn pbjs -t static-module -w es6 --no-bundle -o ${resolve(projectRoot, 'dist/index.js')} ${resolve(projectRoot, 'proto/whisper.proto')}`, {
      stdio: 'inherit'
    });

    console.log('🔄 Fixing imports...');
    const filePath = resolve(projectRoot, 'dist/index.js');
    let content = readFileSync(filePath, 'utf8');

    // Fix the import statement (from your working script)
    content = content.replace(
      /import \* as (\$protobuf) from/g,
      'import $1 from'
    );

    // Add missing extension to the import (from your working script)
    content = content.replace(
      /(['"])protobufjs\/minimal(['"])/g,
      '$1protobufjs/minimal.js$2'
    );

    writeFileSync(filePath, content, 'utf8');
    console.log(`✅ Fixed imports in ${filePath}`);

    console.log('🔄 Generating TypeScript definitions...');
    execSync(`yarn pbts -o ${resolve(projectRoot, 'dist/index.d.ts')} ${resolve(projectRoot, 'dist/index.js')}`, {
      stdio: 'inherit'
    });

    console.log('✅ Compilation completed successfully!');

  } catch (error) {
    console.error('❌ Compilation error:', error.message);
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  compileProtobuf();
}

export { compileProtobuf };