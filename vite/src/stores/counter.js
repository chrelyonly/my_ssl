import { ref, computed } from 'vue'
import { defineStore } from 'pinia'

// 记录分页缓存
export const usePageStore = defineStore('page', () => {
    const currentPage = ref(1) // 默认第一页

    function setCurrentPage(page) {
        currentPage.value = page
    }

    return {
        currentPage,
        setCurrentPage
    }
})

// 记录全局状态
export const getUserLoginStore = defineStore('userLoginStatus', () => {
    const userInfo = ref(undefined)
    const userDetail = ref(undefined)
    // 获取用户登录状态
    function getUserLoginStatus() {
        return !!userInfo.value?.id;
    }
    // 获取用户信息
    function getUserInfo() {
        return userInfo.value;
    }
    // 获取用户详情
    function getUserDetail() {
        return userDetail.value;
    }
    // 设置用户信息
    function setUserInfo(newUserInfo) {
        userInfo.value = newUserInfo;
    }
    // 设置用户详情
    function setUserDetail(newUserDetail) {
        userDetail.value = newUserDetail;
    }
    return {
        getUserLoginStatus,
        getUserInfo,
        setUserInfo,
        setUserDetail,
        getUserDetail,
    }
})


