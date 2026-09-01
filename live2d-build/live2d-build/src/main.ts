import * as PIXI from 'pixi.js';
import { Live2DModel } from 'pixi-live2d-display/cubism4';

(window as any).PIXI = PIXI;

const canvas = document.createElement('canvas');

canvas.id = 'lexicon-live2d-canvas';

Object.assign(canvas.style, {
  position: 'fixed',
  left: '0',
  bottom: '0',
  width: '100%',
  height: '150px',
  zIndex: '3',
  pointerEvents: 'none'
});

document.body.appendChild(canvas);

const app = new PIXI.Application({
  view: canvas,
  width: window.innerWidth,
  height: 150,
  backgroundAlpha: 0,
  antialias: true,
  autoStart: true
});

const pets: {
  model: any;
  speed: number;
  direction: number;
}[] = [];

async function loadPet(
  modelPath: string,
  x: number,
  scale: number,
  speed: number
) {
  const model = await Live2DModel.from(modelPath, {
    autoInteract: false
  });

  model.anchor.set(0.5, 1);
  model.scale.set(scale);
  model.x = x;
  model.y = app.screen.height;

  app.stage.addChild(model);

  pets.push({
    model,
    speed,
    direction: 1
  });
}

async function start() {
  await loadPet(
    '/live2d/tororo/tororo.model3.json',
    150,
    0.16,
    0.35
  );

  await loadPet(
    '/live2d/hijiki/hijiki.model3.json',
    380,
    0.16,
    0.28
  );
}

app.ticker.add(() => {
  for (const pet of pets) {
    const model = pet.model;

    model.x += pet.speed * pet.direction;

    const halfWidth = Math.max(model.width / 2, 35);

    if (model.x >= window.innerWidth - halfWidth) {
      model.x = window.innerWidth - halfWidth;
      pet.direction = -1;
      model.scale.x = -Math.abs(model.scale.x);
    }

    if (model.x <= halfWidth) {
      model.x = halfWidth;
      pet.direction = 1;
      model.scale.x = Math.abs(model.scale.x);
    }

    model.y = app.screen.height;
  }
});

window.addEventListener('resize', () => {
  app.renderer.resize(window.innerWidth, 150);

  for (const pet of pets) {
    pet.model.y = 150;
  }
});

start().catch(error => {
  console.error('Live2D failed to load:', error);
});
