<?php
namespace Smurfy\PHPBBUserBundle\Listener;

use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\HttpKernel;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

class AutologinListener
{
    private $doctrine;

    public function __construct($doctrine, $session, $security, $phpbb_root_path) {
        $this->doctrine = $doctrine;
        $this->session = $session;
        $this->security = $security;

        if(!is_dir($phpbb_root_path)) {
            throw new \Exception('$phpbb_root_path must be a valid directory.');
        }
        $this->phpbb_root_path = $phpbb_root_path;
    }

    public function onKernelRequest(GetResponseEvent $event)
    {
        if (HttpKernel::MASTER_REQUEST != $event->getRequestType()) {
            // ne rien faire si ce n'est pas la requête principale
            return;
        }

        // phpbb global var definition
        global $phpbb_root_path, $phpEx, $db, $cache, $config, $user, $auth, $template;
        $phpbb_root_path = $this->phpbb_root_path;
        if (!defined('IN_PHPBB')) {
            define('IN_PHPBB', true);
        }

        $phpEx = substr(strrchr(__FILE__, '.'), 1);

        $phpbb_root_path = $this->phpbb_root_path;
        require_once $phpbb_root_path.'common.'.$phpEx;
        require_once $phpbb_root_path.'includes/functions_user.'.$phpEx;

        // Start session management
        $user->session_begin();

        $auth->acl($user->data);
        $user->setup('viewforum');

        // We can do the magic here, ie: log the user into our Symfony2 if the user is logged-in on the board
        if ($user->data['is_registered'] AND $user->data['user_id'] != ANONYMOUS)
        {
            $stmt = $this->doctrine->getManager('forum')->getConnection()->prepare('SELECT g.group_name
                                            FROM user_group ug
                                            INNER JOIN groups g ON ug.group_id = g.group_id
                                            WHERE ug.user_id = ?
                                        ');
            $stmt->execute(array($user->data['user_id']));

            $groups = $stmt->fetchAll();

            $roles = null;

            foreach($groups as $group) {
                foreach($group as $groupname) {
                    if($groupname != 'REGISTERED') {
                        $roles[] = 'ROLE_'.strtoupper(str_replace(' ', '_', $groupname));
                    }
                }
            }

            // Make sure that the user have ROLE_USER
            $roles[] = 'ROLE_USER';

            // Create user object
            $userObject = new User($user->data['username'], $user->data['user_password'], $roles, true, true, true, true);  
            
            $token = new UsernamePasswordToken($userObject, null, 'main', $userObject->getRoles());

            $this->security->setToken($token);
        } else {
            // return nothing because the user is connected anonymously
            return;
        }
    }

}