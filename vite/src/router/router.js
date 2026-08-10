import { createRouter, createWebHistory } from "vue-router"
import {ElMessage} from "element-plus";

const routes = [
    {
        path: "/",
        component: () => import("@/views/home.vue"),
        meta: { requiresAuth: true },
        children:[
        ]
    },
]

const router = createRouter({
    history: createWebHistory(),
    routes,
})

// 全局路由守卫
router.beforeEach((to, from, next) => {

    // //  保存用户token信息
    // let accessToken = $getStore({name: "accessToken",});
    //
    // // 已登录访问登录页，直接跳首页
    // if (to.path === "/login" && accessToken) {
    //     ElMessage.info("已登录正在跳转")
    //     next("/")
    //     return
    // }
    //
    // // 需要登录但没有token
    // if (to.meta.requiresAuth && !accessToken) {
    //     ElMessage.info("用户过期,请重新登陆")
    //     next("/login")
    //     return
    // }

    next()
})

export default router