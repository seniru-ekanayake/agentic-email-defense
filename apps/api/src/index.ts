import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';

export async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL || 'info',
    },
  });

  // Security headers & CORS
  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(cors, { origin: true });

  // OpenAPI / Swagger Documentation
  await app.register(swagger, {
    openapi: {
      info: {
        title: 'Agentic Email Exploitation Detection & Response API',
        description: 'Enterprise API for detecting, correlating, and mitigating email rendering & delivery exploits.',
        version: '1.0.0',
      },
      servers: [{ url: 'http://localhost:3000' }],
      components: {
        securitySchemes: {
          apiKey: {
            type: 'apiKey',
            name: 'x-tenant-id',
            in: 'header',
          },
        },
      },
    },
  });

  await app.register(swaggerUi, {
    routePrefix: '/docs',
    uiConfig: {
      docExpansion: 'list',
      deepLinking: false,
    },
  });

  // Register investigation and attack graph routes
  await app.register(require('./routes/investigations').investigationRoutes);

  // Healthcheck
  app.get('/health', async () => ({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
  }));

  // Ingestion routes
  app.post('/api/v1/ingest/email', async (req, reply) => {
    return reply.status(202).send({
      status: 'ACCEPTED',
      job_id: 'job-' + Math.random().toString(36).substring(7),
      message: 'Email enqueued for deterministic parsing and agentic triage.',
    });
  });

  // Response authorization routes
  app.post('/api/v1/responses/:id/approve', async (req, reply) => {
    const { id } = req.params as { id: string };
    return reply.send({
      status: 'EXECUTED',
      approval_token: id,
      action: 'quarantine_email',
      executed_at: new Date().toISOString(),
    });
  });

  // Development simulation endpoints (Strictly disabled in production)
  const isDev = process.env.NODE_ENV !== 'production';
  if (isDev) {
    app.post('/api/v1/simulate/email', async (req, reply) => {
      return reply.send({ simulated: true, type: 'EMAIL', data: req.body });
    });
    app.post('/api/v1/simulate/identity-event', async (req, reply) => {
      return reply.send({ simulated: true, type: 'IDENTITY_EVENT', data: req.body });
    });
    app.post('/api/v1/simulate/session', async (req, reply) => {
      return reply.send({ simulated: true, type: 'SESSION', data: req.body });
    });
    app.post('/api/v1/simulate/asset', async (req, reply) => {
      return reply.send({ simulated: true, type: 'ASSET', data: req.body });
    });
  }

  return app;
}

if (require.main === module) {
  const start = async () => {
    try {
      const app = await buildApp();
      const port = parseInt(process.env.PORT || '3000', 10);
      await app.listen({ port, host: '0.0.0.0' });
      console.log(`Server listening at http://localhost:${port}`);
      console.log(`API documentation available at http://localhost:${port}/docs`);
    } catch (err) {
      console.error(err);
      process.exit(1);
    }
  };
  start();
}
