<?php

declare(strict_types=1);

namespace Plugins\Authorization;

use AlfacodeTeam\PhpServicePlatform\Kernel\Contracts\ModuleContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\EventBus;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Cli\CliPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\HttpPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Worker\WorkerPipeline;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\DatabasePort;
use Plugins\Authorization\API\Contracts\AuthorizationServiceContract;
use Plugins\Authorization\API\Contracts\SubjectAuthorizationContract;
use Plugins\Authorization\Application\Services\AuthorizationService;
use Plugins\Authorization\Application\Services\SubjectAuthorizationService;
use Plugins\Authorization\Engine\Enforcer;
use Plugins\Authorization\Infrastructure\Persistence\DatabasePolicyAdapter;
use Plugins\Database\API\Contracts\DatabaseConnectionManagerContract;

/**
 * Authorization plugin — Casbin RBAC/ABAC policy engine.
 *
 * Ported from the 0.3 framework's Application\Casbin engine. The engine itself
 * lives untouched under Engine/; this Provider wires it into the GDA flow:
 *   - policy storage goes through DatabasePort (DatabasePolicyAdapter)
 *   - the Enforcer is an internal binding (never resolved cross-module)
 *   - only AuthorizationServiceContract is exposed
 */
final class Provider implements ModuleContract
{
    public function solves(): string
    {
        return 'authorization.policy';
    }

    /** @return list<class-string> */
    public function requires(): array
    {
        return ['database.management'];
    }

    /** @return list<class-string> */
    public function exposes(): array
    {
        return [AuthorizationServiceContract::class, SubjectAuthorizationContract::class];
    }

    public function register(ModuleContainer $container): void
    {
        // Casbin policy storage adapter. Policy rules are CONTROL-PLANE data
        // (roles/permissions are global, not tenant data), so pin to the central
        // connection — the same store the authz:seed CLI writes to, so seeded
        // policies are visible to runtime enforcement.
        $container->bindInternal(DatabasePolicyAdapter::class, static fn(ModuleContainer $c) =>
            new DatabasePolicyAdapter(
                $c->make(DatabasePort::class),
                env('AUTHZ_POLICY_TABLE') ?: 'casbin_rule',
            )
        );

        // The Casbin Enforcer — internal, built from the model config plus ONE of
        // two policy sources.
        //
        // AUTHZ_POLICY_FILE selects a CSV on disk instead of the policy table,
        // for deployments that want roles and permissions to live in version
        // control and ship with the release rather than be edited at runtime.
        // CoreEnforcer treats a string adapter as a file path (initWithFile), so
        // the model and the policy are both files in that mode.
        //
        // It is READ-ONLY, and deliberately so: Casbin's FileAdapter implements
        // loadPolicy and savePolicy but throws NotImplementedException from
        // addPolicy/removePolicy. AuthorizationService turns an attempted write
        // into a clear ServiceException rather than letting that escape — see
        // its assertWritable().
        $container->bindInternal(Enforcer::class, static function (ModuleContainer $c) {
            $modelPath  = self::modelPath();
            $policyFile = self::projectPath((string) (env('AUTHZ_POLICY_FILE') ?: ''));

            if ($policyFile === '') {
                return new Enforcer($modelPath, $c->make(DatabasePolicyAdapter::class));
            }

            // Fail here rather than boot with an EMPTY policy. A mistyped path
            // would otherwise deny everything at runtime, which reads like a
            // permissions bug and not like a missing file.
            if (!is_file($policyFile) || !is_readable($policyFile)) {
                throw new \RuntimeException(
                    "AUTHZ_POLICY_FILE [{$policyFile}] is not a readable file. "
                    . 'Unset it to use the policy table, or correct the path.',
                );
            }

            return new Enforcer($modelPath, $policyFile);
        });

        // Published contract.
        $container->bind(AuthorizationServiceContract::class, static fn(ModuleContainer $c) =>
            new AuthorizationService($c->make(Enforcer::class))
        );

        // Published: what a project-resolved Subject's roles allow. Same
        // enforcer, so the same policy source (table or AUTHZ_POLICY_FILE).
        $container->bind(SubjectAuthorizationContract::class, static fn(ModuleContainer $c) =>
            new SubjectAuthorizationService($c->make(Enforcer::class))
        );
    }

    public function boot(HttpPipeline $http, CliPipeline $cli, WorkerPipeline $worker, EventBus $events): void
    {
        // Declarative route filter: "filters": ["can:users,edit"] enforces the
        // Casbin policy for the route (the route must also carry
        // "requires": ["authorization.policy"] so this module is loaded).
        $http->filter('can', \Plugins\Authorization\Infrastructure\Http\Stages\PolicyFilterStage::class);

        // authz:seed — import a policy CSV into the DB policy table. Deferred so
        // only CLI processes pay for it; builds its own enforcer over the
        // central connection (policy rules are control-plane data).
        $cli->defer(static function (CliPipeline $cli): void {
            $c = new ModuleContainer($cli->container());
            $c->setScope('database.management');
            (new \Plugins\Database\Provider())->register($c);

            // Lazy: building an Enforcer loads policy from the DB, so defer it
            // until the command actually runs (not at CLI registration time).
            $enforcerFactory = static function () use ($c): Enforcer {
                $adapter = new DatabasePolicyAdapter(
                    $c->make(\Plugins\Database\API\Contracts\DatabaseConnectionManagerContract::class)->default(),
                    env('AUTHZ_POLICY_TABLE') ?: 'casbin_rule',
                );

                return new Enforcer(self::modelPath(), $adapter);
            };

            $cli->command(new \Plugins\Authorization\Infrastructure\Cli\SeedPolicyCommand(
                $enforcerFactory,
                __DIR__ . '/config/policy.seed.csv',
            ));
        });
    }

    /** AUTHZ_MODEL_PATH, or the bundled domain-less model. */
    private static function modelPath(): string
    {
        return self::projectPath((string) (env('AUTHZ_MODEL_PATH') ?: '')) ?: __DIR__ . '/config/rbac_model.conf';
    }

    /**
     * A configured path, with a RELATIVE one resolved against the project root.
     *
     * `AUTHZ_POLICY_FILE=config/policy.csv` is the natural way to write it, and
     * left as-is it would resolve against the process's working directory —
     * the project root under the CLI, `public/` or `/` under PHP-FPM, wherever
     * `php -S` was started. The same .env would then find the file in one
     * runtime and fail the boot in another.
     */
    private static function projectPath(string $path): string
    {
        $path = trim($path);

        if ($path === '' || str_starts_with($path, '/') || preg_match('#^[A-Za-z]:[\\\\/]#', $path) === 1) {
            return $path;
        }

        return \AlfacodeTeam\PhpServicePlatform\Kernel\Support\Paths::project($path);
    }
}
