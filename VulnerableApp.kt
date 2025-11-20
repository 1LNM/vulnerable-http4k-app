// Import v2 endpoint functions
import { userLensGetHandler } from './handlers/userLensGet';
import { echoLensInjectorHandler } from './handlers/echoLensInjector';

// Existing v1 routes registration
routes.add('/api-v1/some-existing-endpoint', v1Handler);

// Add v2 routes after v1
routes.add('/api-v2/user-lens-get', userLensGetHandler);
routes.add('/api-v2/echo-lens-injector', echoLensInjectorHandler);
// Add additional v2 routes as needed
